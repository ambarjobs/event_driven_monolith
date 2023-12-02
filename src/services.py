# ==================================================================================================
#  Application services
# ==================================================================================================

from typing import Any

import httpx

import schemas as sch
import utils
from database import db


def user_sign_in(credentials: sch.UserCredentials, user_info: sch.UserInfo) -> dict[str, Any]:
    """Sign in service."""
    try:
        version = db.check_document_available('user-credentials', credentials.id)
        return {'status': 'already_signed_in', 'version': version}
    except httpx.HTTPStatusError as err:
        if err.response.status_code == 404:
            hash_ = utils.calc_hash(credentials.password)
            db.sign_in_user(id=credentials.id, hash_=hash_, user_info=user_info)
            return {'status': 'signed_in'}
        return {'status': 'error', 'details': str(err)}
