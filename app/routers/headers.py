import logging

from fastapi import APIRouter, Request

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/headers")
def headers(request: Request) -> dict[str, str]:
    return dict(request.headers)
