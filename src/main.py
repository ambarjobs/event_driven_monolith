from typing import Any
import httpx
from fastapi import FastAPI, status
# from fastapi.responses import JSONResponse

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
    db.init_tables(database_names=[info.name for info in APP_DATABASES_INFO])
    for db_info in APP_DATABASES_INFO:
        db.create_database_indexes(database_info=db_info)
except httpx.HTTPError as exc:
    print(f'Error trying to initialize the databases: {exc}')
    exit(-1)
except httpx.InvalidURL as exc:
    print(f'Invalid database URL: {exc}')
    exit(-1)

app = FastAPI()


# ==================================================================================================
#  Sign in
# ==================================================================================================

@app.post('/signin', status_code=status.HTTP_201_CREATED)
def signin(
    credentials: sch.UserCredentials,
    user_info: sch.UserInfo
) -> dict[str, Any]:
    """Sign in endpoint."""
    return srv.user_sign_in(credentials=credentials, user_info=user_info)

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
