import logging
import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from app.config import get_config
from app.services.oin_cert import generate_oin_certificate

logger = logging.getLogger(__name__)
router = APIRouter()

_OIN_RE = re.compile(r"^\d{20}$")


class OinCertRequest(BaseModel):
    oin: str
    cn: str

    @field_validator("oin")
    @classmethod
    def oin_must_be_20_digits(cls, v: str) -> str:
        if not _OIN_RE.match(v):
            raise ValueError("OIN must be exactly 20 digits")
        return v


class OinCertResponse(BaseModel):
    certificate: str
    private_key: str


@router.post("/oin-cert", response_model=OinCertResponse)
def create_oin_cert(body: OinCertRequest) -> OinCertResponse:
    config = get_config()
    ca_base = config.ca.oin_ca_dir

    ca_cert_path = f"{ca_base}/oin-ca.crt"
    ca_key_path = f"{ca_base}/oin-ca.key"

    try:
        cert_pem, key_pem = generate_oin_certificate(
            oin=body.oin,
            cn=body.cn,
            ca_cert_path=ca_cert_path,
            ca_key_path=ca_key_path,
        )
    except FileNotFoundError as e:
        logger.error("CA file not found: %s", e)
        raise HTTPException(status_code=500, detail="CA certificate or key not found") from e
    except Exception as e:
        logger.error("Certificate generation failed: %s", e)
        raise HTTPException(status_code=500, detail="Failed to generate certificate") from e

    return OinCertResponse(certificate=cert_pem, private_key=key_pem)
