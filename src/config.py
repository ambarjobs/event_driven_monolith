####################################################################################################
# FastAPI configuration file.
####################################################################################################
import os

# --------------------------------------------------------------------------------------------------
#  Database
# --------------------------------------------------------------------------------------------------
db_protocol = 'http'
db_host = 'couchdb'
db_port = 5984
DB_URL = f'{db_protocol}://{db_host}:{db_port}'

USER_CREDENTIALS_DB_NAME = 'user-credentials'
USER_INFO_DB_NAME = 'user-info'


# --------------------------------------------------------------------------------------------------
#  Tokens
# --------------------------------------------------------------------------------------------------
ACCESS_TOKEN_SECRET_KEY = os.environ.get('ACCESS_TOKEN_SECRET_KEY')
TOKEN_ALGORITHM = 'HS256'
TOKEN_DEFAULT_EXPIRATION_HOURS = 24


# --------------------------------------------------------------------------------------------------
#  Email validation
# --------------------------------------------------------------------------------------------------
EMAIL_VALIDATION_TIMEOUT_HOURS = 24


# --------------------------------------------------------------------------------------------------
#  Testing
# --------------------------------------------------------------------------------------------------
TEST_PREFIX = 'test'
