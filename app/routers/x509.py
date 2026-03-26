import logging
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi import APIRouter, HTTPException, Request

logger = logging.getLogger(__name__)
router = APIRouter()


def _format_name(name: x509.Name) -> dict[str, str]:
    return {attr.oid._name: attr.value for attr in name}


def _format_datetime(dt: datetime) -> str:
    return dt.isoformat()


def _format_extensions(cert: x509.Certificate) -> list[dict[str, object]]:
    result = []
    for ext in cert.extensions:
        entry: dict[str, object] = {
            "oid": ext.oid.dotted_string,
            "name": ext.oid._name,
            "critical": ext.critical,
        }
        try:
            value = ext.value
            if isinstance(value, x509.SubjectAlternativeName):
                entry["value"] = [str(name) for name in value]
            elif isinstance(value, x509.KeyUsage):
                usage = []
                for attr in [
                    "digital_signature", "content_commitment", "key_encipherment",
                    "data_encipherment", "key_agreement", "key_cert_sign",
                    "crl_sign", "encipher_only", "decipher_only",
                ]:
                    try:
                        if getattr(value, attr):
                            usage.append(attr)
                    except x509.extensions.ExtensionNotFound:
                        pass
                entry["value"] = usage
            elif isinstance(value, x509.ExtendedKeyUsage):
                entry["value"] = [oid._name for oid in value]
            elif isinstance(value, x509.BasicConstraints):
                entry["value"] = {"ca": value.ca, "path_length": value.path_length}
            elif isinstance(value, x509.SubjectKeyIdentifier):
                entry["value"] = value.key_identifier.hex()
            elif isinstance(value, x509.AuthorityKeyIdentifier):
                entry["value"] = {
                    "key_identifier": value.key_identifier.hex() if value.key_identifier else None,
                    "authority_cert_serial_number": value.authority_cert_serial_number,
                }
            elif isinstance(value, x509.CRLDistributionPoints):
                points = []
                for dp in value:
                    if dp.full_name:
                        points.extend([str(n) for n in dp.full_name])
                entry["value"] = points
            elif isinstance(value, x509.AuthorityInformationAccess):
                entry["value"] = [
                    {"access_method": desc.access_method._name, "access_location": str(desc.access_location)}
                    for desc in value
                ]
            elif isinstance(value, x509.CertificatePolicies):
                entry["value"] = [str(policy.policy_identifier.dotted_string) for policy in value]
            else:
                entry["value"] = str(value)
        except Exception as e:
            entry["value"] = f"<could not parse: {e}>"
        result.append(entry)
    return result


@router.post("/x509/parse")
async def parse_x509(request: Request) -> dict[str, object]:
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="No certificate provided")

    text = body.decode("utf-8").strip()

    try:
        if "-----BEGIN" in text:
            cert = x509.load_pem_x509_certificate(text.encode())
        else:
            import base64
            cert = x509.load_der_x509_certificate(base64.b64decode(text))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse certificate: {e}")

    pub_key = cert.public_key()
    pub_key_info: dict[str, object] = {"algorithm": type(pub_key).__name__}
    try:
        pub_key_info["pem"] = pub_key.public_bytes(Encoding.PEM).decode()  # type: ignore
    except Exception:
        pass

    return {
        "subject": _format_name(cert.subject),
        "issuer": _format_name(cert.issuer),
        "serial_number": str(cert.serial_number),
        "serial_number_hex": format(cert.serial_number, "x"),
        "not_valid_before": _format_datetime(cert.not_valid_before_utc),
        "not_valid_after": _format_datetime(cert.not_valid_after_utc),
        "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
        "signature_algorithm_name": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
        "version": cert.version.name,
        "public_key": pub_key_info,
        "fingerprint_sha256": cert.fingerprint(cert.signature_hash_algorithm.__class__()).hex()
        if cert.signature_hash_algorithm else None,
        "extensions": _format_extensions(cert),
    }
