import logging

from fastapi import APIRouter, Response

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/httpstatus/{status_code}")
def httpstatus(status_code: int) -> Response:
    return Response(status_code=status_code)
