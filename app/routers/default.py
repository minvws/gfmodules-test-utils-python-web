import json
import logging
from pathlib import Path

from fastapi import APIRouter, Response

logger = logging.getLogger(__name__)
router = APIRouter()

# https://www.patorjk.com/software/taag/#p=display&f=Doom&t=Skeleton
LOGO = r"""
 _____ _____ _____ _____   _   _ _____ _____ _      _____
|_   _|  ___/  ___|_   _| | | | |_   _|_   _| |    /  ___|
  | | | |__ \ `--.  | |   | | | | | |   | | | |    \ `--.
  | | |  __| `--. \ | |   | | | | | |   | | | |     `--. \
  | | | |___/\__/ / | |   | |_| | | |  _| |_| |____/\__/ /
  \_/ \____/\____/  \_/    \___/  \_/  \___/\_____/\____/
"""


@router.get("/")
def index() -> Response:
    content = LOGO

    try:
        with open(Path(__file__).parent.parent.parent / "version.json", "r") as file:
            data = json.load(file)
            content += "\nVersion: %s\nCommit: %s" % (data["version"], data["git_ref"])
    except BaseException as e:
        content += "\nNo version information found"
        logger.info("Version info could not be loaded: %s" % e)

    return Response(content)


@router.get("/version.json")
def version_json() -> Response:
    try:
        with open(Path(__file__).parent.parent.parent / "version.json", "r") as file:
            content = file.read()
    except BaseException as e:
        logger.info("Version info could not be loaded: %s" % e)
        return Response(status_code=404)

    return Response(content)
