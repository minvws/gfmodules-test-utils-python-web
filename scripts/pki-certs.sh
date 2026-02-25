#!/usr/bin/env bash
set -euo pipefail

SECRETS_DIR="${SECRETS_DIR:-./pki}"
CN_BASE="${CN_BASE:-gfmodules-test}"
PFX_PASS="${PFX_PASS:-notsecret}"

mkdir -p "$SECRETS_DIR/ca"

REGISTRY_FILE="${REGISTRY_FILE:-$SECRETS_DIR/cert-registry.tsv}"

registry_init() {
  if [[ ! -f "$REGISTRY_FILE" ]]; then
    printf "created_at\tgroup\tcn\tura\tldn_intermediate\tuzi_intermediate\tldn_dir\tuzi_dir\n" >"$REGISTRY_FILE"
  fi
}

registry_append() {
  local group="$1" cn="$2" ura="$3" ldn_ca="$4" uzi_ca="$5" ldn_dir="$6" uzi_dir="$7"
  local ts
  ts="$(date -Iseconds)"
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$ts" "$group" "$cn" "$ura" "$ldn_ca" "$uzi_ca" "$ldn_dir" "$uzi_dir" >>"$REGISTRY_FILE"
}

# -----------------------------
# UI helpers (dialog preferred, whiptail fallback)
# -----------------------------
UI="none"
if command -v dialog >/dev/null 2>&1; then
  UI="dialog"
elif command -v whiptail >/dev/null 2>&1; then
  UI="whiptail"
else
  echo "ERROR: need 'dialog' or 'whiptail' installed." >&2
  exit 1
fi

ui_menu() {
  local title="$1"
  shift
  local prompt="$1"
  shift
  if [[ "$UI" == "dialog" ]]; then
    dialog --clear --stdout --title "$title" --menu "$prompt" 0 0 0 "$@"
  else
    whiptail --title "$title" --menu "$prompt" 20 80 10 "$@" 3>&1 1>&2 2>&3
  fi
}

ui_input() {
  local title="$1"
  local prompt="$2"
  local initial="${3:-}"
  if [[ "$UI" == "dialog" ]]; then
    dialog --clear --stdout --title "$title" --inputbox "$prompt" 10 80 "$initial"
  else
    whiptail --title "$title" --inputbox "$prompt" 10 80 "$initial" 3>&1 1>&2 2>&3
  fi
}

ui_yesno() {
  local title="$1"
  local prompt="$2"
  if [[ "$UI" == "dialog" ]]; then
    dialog --clear --title "$title" --yesno "$prompt" 10 80
  else
    whiptail --title "$title" --yesno "$prompt" 10 80
  fi
}

ui_msg() {
  local title="$1"
  local msg="$2"
  if [[ "$UI" == "dialog" ]]; then
    dialog --clear --title "$title" --msgbox "$msg" 14 80
  else
    whiptail --title "$title" --msgbox "$msg" 14 80
  fi
}

# Multiline CSR paste into a temp file:
# - dialog: editbox (ncurses)
# - whiptail: open $EDITOR on the temp file (still terminal copy/paste)
ui_get_csr_to_file() {
  local out_file="$1"

  local tmp
  tmp="$(mktemp)"
  cat >"$tmp" <<'EOF'
-----BEGIN CERTIFICATE REQUEST-----
# Paste CSR here (including BEGIN/END lines)
-----END CERTIFICATE REQUEST-----
EOF

  if [[ "$UI" == "dialog" ]]; then
    dialog --clear --title "Paste CSR" --editbox "$tmp" 22 80 2>"$out_file"
  else
    local editor="${EDITOR:-nano}"
    echo "Opening editor to paste CSR: $editor" >&2
    "$editor" "$tmp"
    cp "$tmp" "$out_file"
  fi

  rm -f "$tmp"
}

validate_csr_file() {
  local csr="$1"

  # Must exist and be non-empty
  [[ -s "$csr" ]] || return 1

  # Must parse as a CSR
  openssl req -in "$csr" -noout >/dev/null 2>&1 || return 1

  # Must be RSA
  openssl req -in "$csr" -noout -text 2>/dev/null | grep -q "Public Key Algorithm: rsaEncryption" || return 1

  # Enforce key policy:
  # - RSA must be >= 3072 bits
  local pub_bits
  pub_bits="$(openssl req -in "$csr" -noout -text 2>/dev/null | sed -nE 's/^\s*Public-Key: \(([0-9]+) bit\).*/\1/p' | head -n1)"
  [[ -n "$pub_bits" ]] || return 1

  if ((pub_bits < 2048)); then
    return 1
  fi

  return 0
}

# -----------------------------
# PKI creation (same idea as your script)
# -----------------------------
create_ca() {
  local cert_name="$1"

  echo "* Generating CA certificate for ${cert_name}"

  if [[ -f "$SECRETS_DIR/ca/${cert_name}.crt" ]]; then
    echo "! CA certificate already exists. Skipping"
    return
  fi

  openssl genrsa -out "$SECRETS_DIR/ca/${cert_name}.key" 4096
  openssl req -x509 -new -nodes -sha256 -days 1024 \
    -key "$SECRETS_DIR/ca/${cert_name}.key" \
    -out "$SECRETS_DIR/ca/${cert_name}.crt" \
    -subj "/C=NL/L=Den Haag/O=MinVWS/OU=iRealisatie/CN=${CN_BASE}-${cert_name}"

  openssl pkcs12 -export \
    -out "$SECRETS_DIR/ca/${cert_name}.pfx" \
    -inkey "$SECRETS_DIR/ca/${cert_name}.key" \
    -in "$SECRETS_DIR/ca/${cert_name}.crt" \
    -passout "pass:${PFX_PASS}"
}

create_intermediate() {
  local im_name="$1"
  local ca_name="$2"

  echo "* Generating intermediate certificate for ${im_name} based on ${ca_name}"

  if [[ -f "$SECRETS_DIR/ca/${im_name}.crt" ]]; then
    echo "! Intermediate certificate already exists. Skipping"
    return
  fi

  openssl genrsa -out "$SECRETS_DIR/ca/${im_name}.key" 4096
  openssl req -new -sha256 \
    -key "$SECRETS_DIR/ca/${im_name}.key" \
    -out "$SECRETS_DIR/ca/${im_name}.csr" \
    -subj "/C=NL/L=Den Haag/O=MinVWS/OU=iRealisatie/CN=${CN_BASE}-${im_name}"

  openssl x509 -req -sha256 -days 1024 \
    -in "$SECRETS_DIR/ca/${im_name}.csr" \
    -CA "$SECRETS_DIR/ca/${ca_name}.crt" \
    -CAkey "$SECRETS_DIR/ca/${ca_name}.key" \
    -CAcreateserial \
    -out "$SECRETS_DIR/ca/${im_name}.crt" \
    -extfile <(echo "basicConstraints=critical,CA:TRUE,pathlen:0")

  rm -f "$SECRETS_DIR/ca/${im_name}.csr"

  openssl pkcs12 -export \
    -out "$SECRETS_DIR/ca/${im_name}.pfx" \
    -inkey "$SECRETS_DIR/ca/${im_name}.key" \
    -in "$SECRETS_DIR/ca/${im_name}.crt" \
    -passout "pass:${PFX_PASS}"
}

write_chain_files() {
  local full_base="$1"
  local full_ca_base="$2"
  local full_root_ca_base="$3"

  # root CA copy (handy for k8s secrets etc)
  cp "${full_root_ca_base}.crt" "$(dirname "${full_base}.crt")/" 2>/dev/null || true

  # full chain
  cat "${full_base}.crt" >"${full_base}-chain.crt"
  cat "${full_ca_base}.crt" >>"${full_base}-chain.crt"
  cat "${full_root_ca_base}.crt" >>"${full_base}-chain.crt"
}

create_ldn_client_cert_with_optional_csr() {
  local cert_name="$1"
  local ca_name="$2"
  local root_ca_name="$3"
  local csr_file="$4" # if valid => use it; else generate

  echo "* Generating LDN client certificate for ${cert_name} based on ${ca_name}"

  local full_base="$SECRETS_DIR/${cert_name}-${ca_name}/${cert_name}-ldn"
  local full_ca_base="$SECRETS_DIR/ca/${ca_name}"
  local full_root_ca_base="$SECRETS_DIR/ca/${root_ca_name}"

  if [[ -f "${full_base}.crt" ]]; then
    echo "! LDN certificate already exists. Skipping"
    return
  fi

  mkdir -p "$(dirname "${full_base}.crt")"

  if validate_csr_file "$csr_file"; then
    # CSR provided: do not generate key here (so no PFX unless key also exists locally)
    cp "$csr_file" "${full_base}.csr"
  else
    openssl genrsa -out "${full_base}.key" 3072
    openssl rsa -in "${full_base}.key" -pubout >"${full_base}.pub"

    openssl req -new -sha256 \
      -key "${full_base}.key" \
      -subj "/C=NL/L=Den Haag/O=MinVWS/OU=iRealisatie/CN=${cert_name}" \
      -out "${full_base}.csr"
  fi

  openssl x509 -req -days 500 -sha256 \
    -in "${full_base}.csr" \
    -CA "${full_ca_base}.crt" \
    -CAkey "${full_ca_base}.key" \
    -CAcreateserial \
    -out "${full_base}.crt"

  rm -f "${full_base}.csr"

  if [[ -f "${full_base}.key" ]]; then
    chmod +r "${full_base}.key"
    openssl pkcs12 -export \
      -out "${full_base}.pfx" \
      -inkey "${full_base}.key" \
      -in "${full_base}.crt" \
      -certfile "${full_ca_base}-chain.crt" \
      -passout "pass:${PFX_PASS}"
  fi

  write_chain_files "$full_base" "$full_ca_base" "$full_root_ca_base"
}

create_uzi_cert_with_optional_csr() {
  local cert_name="$1"
  local ura_number="$2"
  local ca_name="$3"
  local root_ca_name="$4"
  local csr_file="$5" # if valid => use it; else generate

  echo "* Generating UZI certificate for ${cert_name} based on ${ca_name}"

  local full_base="$SECRETS_DIR/${cert_name}-${ca_name}/${cert_name}-uzi"
  local full_ca_base="$SECRETS_DIR/ca/${ca_name}"
  local full_root_ca_base="$SECRETS_DIR/ca/${root_ca_name}"

  if [[ -f "${full_base}.crt" ]]; then
    echo "! UZI certificate already exists. Skipping"
    return
  fi

  mkdir -p "$(dirname "${full_base}.crt")"

  # UZI SAN
  local san="otherName:2.5.5.5;IA5STRING:2.16.528.1.1003.1.3.5.5.2-1-12345678-S-${ura_number}-00.000-00000000,DNS:${cert_name}"

  if validate_csr_file "$csr_file"; then
    # CSR provided: do not generate key here (so no PFX unless you extend the script to paste key too)
    cp "$csr_file" "${full_base}.csr"
  else
    openssl genrsa -out "${full_base}.key" 3072
    openssl rsa -in "${full_base}.key" -pubout >"${full_base}.pub"

    openssl req -new -sha256 \
      -key "${full_base}.key" \
      -subj "/C=NL/L=Den Haag/O=MinVWS/OU=iRealisatie/CN=${cert_name}/serialNumber=1234ABCD" \
      -out "${full_base}.csr"
  fi

  extfile="${full_base}.ext"
  cat >"$extfile" <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
certificatePolicies = 2.16.528.1.1003.1.2.8.6
subjectAltName = ${san}
EOF

  openssl x509 -req -days 500 -sha256 \
    -in "${full_base}.csr" \
    -CA "${full_ca_base}.crt" \
    -CAkey "${full_ca_base}.key" \
    -CAcreateserial \
    -extfile "$extfile" \
    -out "${full_base}.crt"

  rm -f "${full_base}.csr"
  rm -f "${full_base}.ext"

  write_chain_files "$full_base" "$full_ca_base" "$full_root_ca_base"

  if [[ -f "${full_base}.key" ]]; then
    chmod +r "${full_base}.key"
    openssl pkcs12 -export \
      -out "${full_base}.pfx" \
      -inkey "${full_base}.key" \
      -in "${full_base}.crt" \
      -certfile "${full_ca_base}-chain.crt" \
      -passout "pass:${PFX_PASS}"
  fi

}

bootstrap_pki() {
  create_ca "ldn-ca"
  create_intermediate "ldn-external-intermediate" "ldn-ca"
  create_intermediate "ldn-dev-intermediate" "ldn-ca"
  create_intermediate "ldn-services-intermediate" "ldn-ca"

  create_ca "uzi-ca"
  create_intermediate "uzi-external-intermediate" "uzi-ca"
  create_intermediate "uzi-dev-intermediate" "uzi-ca"
  create_intermediate "uzi-services-intermediate" "uzi-ca"
}

# -----------------------------
# Wizard flow (always creates BOTH LDN + UZI)
# -----------------------------
pick_group() {
  ui_menu "Group" "Select intermediate group:" \
    external "External parties that will connect to the test-env" \
    dev "Internal GFModule developers" \
    service "For services running inside the test-env (nvi, prs etc)"
}

map_group_to_ca_pair() {
  local group="$1"
  case "$group" in
  external) echo "ldn-external-intermediate ldn-ca uzi-external-intermediate uzi-ca" ;;
  dev) echo "ldn-dev-intermediate ldn-ca uzi-dev-intermediate uzi-ca" ;;
  service) echo "ldn-services-intermediate ldn-ca uzi-services-intermediate uzi-ca" ;;
  *) return 1 ;;
  esac
}

wizard_run_once() {
  local group cert_name ura
  group="$(pick_group)"

  cert_name="$(ui_input "Name" "Certificate base name (CN / DNS), e.g. nvi / prs, or firstname-lastname:" "")"
  [[ -n "${cert_name// /}" ]] || {
    ui_msg "Error" "Name is required."
    return 1
  }

  ura="$(ui_input "URA number" "URA number for UZI certificate (e.g. 90000901):" "")"
  [[ -n "${ura// /}" ]] || {
    ui_msg "Error" "URA number is required."
    return 1
  }

  local ldn_ca ldn_root uzi_ca uzi_root
  read -r ldn_ca ldn_root uzi_ca uzi_root < <(map_group_to_ca_pair "$group")

  # CSR for UZI: optional paste
  local csr_tmp
  csr_tmp="$(mktemp)"
  trap 'rm -f "$csr_tmp"' RETURN
  : >"$csr_tmp"

  if ui_yesno "CSR" "Do you want to paste a CSR for this certificate pair (LDN + UZI)?\n\nYes = use pasted CSR for both\nNo  = generate key + CSR automatically"; then
    ui_get_csr_to_file "$csr_tmp"
    if ! validate_csr_file "$csr_tmp"; then
      ui_msg "Error" "CSR is not valid (openssl req -noout failed)."
      return 1
    fi
  fi

  # Always create BOTH:
  create_ldn_client_cert_with_optional_csr "$cert_name" "$ldn_ca" "$ldn_root" "$csr_tmp"
  create_uzi_cert_with_optional_csr "$cert_name" "$ura" "$uzi_ca" "$uzi_root" "$csr_tmp"

  local ldn_dir="$SECRETS_DIR/${cert_name}-${ldn_ca}"
  local uzi_dir="$SECRETS_DIR/${cert_name}-${uzi_ca}"
  registry_append "$group" "$cert_name" "$ura" "$ldn_ca" "$uzi_ca" "$ldn_dir" "$uzi_dir"

  ui_msg "Done" \
    "Created assets under:
- $SECRETS_DIR/${cert_name}-${ldn_ca}/   (LDN: ${cert_name}-ldn.*)
- $SECRETS_DIR/${cert_name}-${uzi_ca}/   (UZI: ${cert_name}-uzi.*)

Note: if you provided a CSR for UZI, no private key exists here => no .pfx for UZI unless you also supply the key."
}

main() {
  bootstrap_pki
  registry_init

  while true; do
    wizard_run_once || true
    if ! ui_yesno "Continue" "Create another (LDN+UZI) certificate pair?"; then
      break
    fi
  done

  [[ "$UI" == "dialog" ]] && clear
}

main "$@"
