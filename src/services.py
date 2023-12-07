# ==================================================================================================
#  Application services
# ==================================================================================================

from typing import Any

import httpx

import config
import schemas as sch
import utils
from database import db


def user_sign_in(
    credentials: sch.UserCredentials,
    user_info: sch.UserInfo,
) -> dict[str, Any]:
    """Sign in service."""
    try:
        version = db.check_document_available(config.USER_CREDENTIALS_DB_NAME, credentials.id)
        if version is None:
            hash_ = utils.calc_hash(credentials.password)
            db.sign_in_user(
                id=credentials.id,
                hash_=hash_,
                user_info=user_info,
            )
            return {'status': 'signed_in'}
        return {'status': 'already_signed_in', 'version': version}
    except httpx.HTTPStatusError as err:
        return {
            'status': 'error',
            'details': {
                'description': str(err),
                'status_code': err.response.status_code
            }
        }
