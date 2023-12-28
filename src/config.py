####################################################################################################
# FastAPI configuration file.
####################################################################################################
import os
import sys

# --------------------------------------------------------------------------------------------------
#  Testing
# --------------------------------------------------------------------------------------------------
IN_TEST = 'pytest' in sys.modules

TEST_PREFIX = 'test'

# --------------------------------------------------------------------------------------------------
#  Database
# --------------------------------------------------------------------------------------------------
db_protocol = 'http'
db_host = 'couchdb'
db_port = 5984
DB_URL = f'{db_protocol}://{db_host}:{db_port}'

# Use prefixed database names when testing.
DB_PREFIX = f'{TEST_PREFIX}-' if IN_TEST else ''

USER_CREDENTIALS_DB_NAME = f'{DB_PREFIX}user-credentials'
USER_INFO_DB_NAME = f'{DB_PREFIX}user-info'
EMAIL_CONFIRMATION_DB_NAME = f'{DB_PREFIX}email-confirmation'

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
#  RabbitMQ
# --------------------------------------------------------------------------------------------------
RABBIT_HOST = 'rabbitmq'
RABBIT_PORT = 5672
RABBIT_HEARTBEAT_TIMEOUT = 6 * 60
RABBIT_BLOCKED_CONNECTION_TIMEOUT = 3 * 60
