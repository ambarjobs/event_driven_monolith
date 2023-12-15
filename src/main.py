# ==================================================================================================
#  Application endpoints
# ==================================================================================================
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import SecretStr

import schemas as sch
import services as srv
from database import DatabaseInfo, db, Index


APP_DATABASES_INFO = [
    DatabaseInfo(
        name='user-credentials',
        indexes=[Index(name='user-credentials-id-index', fields=['_id'])]
    ),
    DatabaseInfo(name='user-info', indexes=[Index(name='user-info-id-index', fields=['_id'])]),
]

try:
    db.init_databases(database_names=[info.name for info in APP_DATABASES_INFO])
    for db_info in APP_DATABASES_INFO:
        db.create_database_indexes(database_info=db_info)
except httpx.HTTPError as err:
    print(f'Error trying to initialize the databases: {err}')
    exit(-1)
except httpx.InvalidURL as err:
    print(f'Invalid database URL: {err}')
    exit(-1)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

app = FastAPI()


# ==================================================================================================
#  General functions
# ==================================================================================================
def oauth2form_to_credentials(form_data: OAuth2PasswordRequestForm) -> sch.UserCredentials:
    """Get the UserCredentials object corresponding to the OAuth2 request form."""
    return sch.UserCredentials(id=form_data.username, password=SecretStr(form_data.password))

# ==================================================================================================
#  Sign in
# ==================================================================================================
@app.post('/signin')
def signin(
    credentials: sch.UserCredentials,
    user_info: sch.UserInfo
) -> JSONResponse:
    """Sign in endpoint."""
    result = srv.user_sign_in(credentials=credentials, user_info=user_info)
    result_sch = sch.ServiceStatus(**result)
    if result_sch.status == 'user_already_signed_in':
        return JSONResponse(content=result, status_code=status.HTTP_409_CONFLICT)
    if result_sch.error and result_sch.status == 'http_error':
        return JSONResponse(
            content=result,
            status_code=result_sch.details.error_code or 0
        )
    return JSONResponse(content=result, status_code=status.HTTP_201_CREATED)


@app.post('/login')
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()]) -> JSONResponse:
    credentials =oauth2form_to_credentials(form_data=form)
    login_data = srv.authentication(credentials=credentials)
    login_status = sch.ServiceStatus(**login_data)
    match login_status:
        case (sch.ServiceStatus(status='incorrect_login_credentials') |
            sch.ServiceStatus(status='email_not_validated') |
            sch.ServiceStatus(status='user_already_signed_in')
        ):
            return JSONResponse(content=login_data, status_code=status.HTTP_401_UNAUTHORIZED)
        case sch.ServiceStatus(status='http_error'):
            return JSONResponse(content=login_data, status_code=login_status.details.error_code)
        case _:
            return JSONResponse(content=login_data, status_code=status.HTTP_200_OK)


@app.get('/tst')
def teste(token: Annotated[str, Depends(oauth2_scheme)]):
    return {}
# @app.post('/stores/add', status_code=status.HTTP_201_CREATED)
# def add_store(store: srlz.StoreIn):
#     """Adiciona uma loja."""
#     try:
#         with db_session:
#             store_name = store.name
#             mdl.Store(name=store_name)
#             return {'msg': f'A loja [{store_name}] foi adicionada.'}
#     except TransactionIntegrityError:
#         content = {
#             'error': f'Loja [{store_name}] já existe.',
#             'code': ErrorCode.store.unique,
#         }
#         status_code = status.HTTP_400_BAD_REQUEST
#         return JSONResponse(content=content, status_code=status_code)
