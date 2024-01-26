# ==================================================================================================
#  Database module tests
# ==================================================================================================
import os
from unittest import mock

import httpx
import pytest
from fastapi import status

import config
import utils
from database import DatabaseInfo, DbCredentials, Index, db
from exceptions import InvalidCouchDBCredentialError
from tests.helpers import access_database, Db


class TestDatabase:
    # ----------------------------------------------------------------------------------------------
    #   CouchDB._get_credentials() method
    # ----------------------------------------------------------------------------------------------
    def test_get_credentials__general_case(self) -> None:
        COUCHDB_USER = 'couchdb_user'
        COUCHDB_PASSWORD = 'couchdb_password'

        os.environ['COUCHDB_USER'] = COUCHDB_USER
        os.environ['COUCHDB_PASSWORD'] = COUCHDB_PASSWORD

        db_admin_credentials = db._get_credentials(
            'COUCHDB_USER',
            'COUCHDB_PASSWORD'
        )

        assert db_admin_credentials.user == COUCHDB_USER
        assert db_admin_credentials.password == COUCHDB_PASSWORD

    def test_get_credentials__no_user_environment_variable(self) -> None:
        COUCHDB_PASSWORD = 'couchdb_password'

        os.environ['COUCHDB_USER'] = ''
        os.environ['COUCHDB_PASSWORD'] = COUCHDB_PASSWORD

        with pytest.raises(InvalidCouchDBCredentialError):
            db_admin_credentials = db._get_credentials(
                'COUCHDB_USER',
                'COUCHDB_PASSWORD'
            )
            db_admin_credentials

    def test_get_credentials__no_password_environment_variable(self) -> None:
        COUCHDB_USER = 'couchdb_user'

        os.environ['COUCHDB_USER'] = COUCHDB_USER
        os.environ['COUCHDB_PASSWORD'] = ''

        with pytest.raises(InvalidCouchDBCredentialError):
            db_admin_credentials = db._get_credentials(
                'COUCHDB_USER',
                'COUCHDB_PASSWORD'
            )
            db_admin_credentials

    # ----------------------------------------------------------------------------------------------
    #   CouchDB.create_database() method
    # ----------------------------------------------------------------------------------------------
    def test_create_database__general_case(self) -> None:
        database_name = f'{config.TEST_PREFIX}-database'
        try:
            db.create_database(database_name=database_name)

            response = access_database(
                access_function=httpx.get,
                url_parts=['_all_dbs'],
                credentials=db.admin_credentials,
            )

            assert database_name in response
        finally:
            access_database(
                access_function=httpx.delete,
                url_parts=[database_name],
                credentials=db.admin_credentials,
            )

    def test_create_database__invalid_name(self) -> None:
        # Uppercase letters are invalid in CouchDB databases
        database_name = 'INVALID-NAME'
        with pytest.raises(httpx.HTTPStatusError, match="Client error '400 Bad Request'"):
            db.create_database(database_name=database_name)

    def test_create_database__existing_database(self) -> None:
        database_name = f'{config.TEST_PREFIX}-database'
        try:
            db.create_database(database_name=database_name)

            # Try to create the same database
            db.create_database(database_name=database_name)

            response = access_database(
                access_function=httpx.get,
                url_parts=['_all_dbs'],
                credentials=db.admin_credentials,
            )

            # No exception is generated by the method
            assert database_name in response
            # No duplicate database is created
            assert response.count(database_name) == 1

        finally:
            access_database(
                access_function=httpx.delete,
                url_parts=[database_name],
                credentials=db.admin_credentials,
            )

    # ----------------------------------------------------------------------------------------------
    #   CouchDB.set_app_permissions_on_database() method
    # ----------------------------------------------------------------------------------------------
    def test_set_app_permissions_on_database__general_case(self, test_db: Db) -> None:
        database_name = test_db.database_name
        expected_permissions = {
            "members": {
                "roles": ["_admin"]
            },
            "admins": {
                "roles": ["_admin", "app"]
            }
        }

        try:
            test_db.create()
            db.set_app_permissions_on_database(database_name=database_name)

            response = access_database(
                access_function=httpx.get,
                url_parts=[database_name, '_security'],
                credentials=db.admin_credentials,
            )

            assert response == expected_permissions
        finally:
            test_db.delete()

    def test_set_app_permissions_on_database__inexistent_database(self) -> None:
        database_name = 'inexistent-database'

        with pytest.raises(httpx.HTTPStatusError, match="Client error '404 Object Not Found'"):
            db.set_app_permissions_on_database(database_name=database_name)

    # ----------------------------------------------------------------------------------------------
    #   CouchDB.create_database_indexes() method
    # ----------------------------------------------------------------------------------------------
    def test_create_database_indexes__general_case(self, test_db: Db) -> None:
        database_name = test_db.database_name
        indexes = [
            Index(name='first-index', fields=['field1', 'field2']),
            Index(name='second-index', fields=['field2', 'field3']),
        ]
        database_info = DatabaseInfo(name=database_name, indexes=indexes)

        test_db.create()
        test_db.add_permissions()
        db.create_database_indexes(database_info=database_info)

        database_indexes_response = access_database(
            access_function=httpx.get,
            url_parts=[database_name, '_index'],
            credentials=db.app_credentials,
        )

        all_database_indexes = utils.deep_traversal(database_indexes_response, 'indexes')
        if all_database_indexes is None:
            raise AttributeError
        user_indexes = [
            index for index in all_database_indexes
            if utils.deep_traversal(index, 'type') == 'json'
        ]

        index_names = [index.name for index in indexes]

        for index in user_indexes:
            db_index_name = utils.deep_traversal(index, 'ddoc').removeprefix('_design/')
            assert db_index_name in index_names

            index_fields = utils.first(
                [index.fields for index in indexes if index.name == db_index_name]
            )
            if index_fields is None:
                raise ValueError
            db_index_fields = [
                key for field_dict in utils.deep_traversal(index, 'def', 'fields')
                for key in field_dict.keys()
            ]
            for field in db_index_fields:
                assert field in index_fields

    # ----------------------------------------------------------------------------------------------
    #   CouchDB.check_document_available() method
    # ----------------------------------------------------------------------------------------------
    def test_check_document_available__general_case(self, test_db: Db, user_id: str) -> None:
        database_name = test_db.database_name
        document_id = user_id
        body = {'field': 'value'}
        test_db.create()
        test_db.add_permissions()
        response = test_db.create_document(document_id= document_id, body=body)
        revision = response.get('rev')

        response_rev = db.check_document_available(
            database_name=database_name,
            document_id=document_id
        )
        assert response_rev == revision

    def test_check_document_available__document_not_found(self, test_db: Db) -> None:
        database_name = test_db.database_name
        document_id = 'test_document'

        test_db.create()
        test_db.add_permissions()
        # The document wasn't created.

        response_rev = db.check_document_available(
            database_name=database_name,
            document_id=document_id
        )

        assert response_rev is None

    # ----------------------------------------------------------------------------------------------
    #   CouchDB.get_document_by_id() method
    # ----------------------------------------------------------------------------------------------
    def test_get_document_by_id__general_case(
        self,
        test_db: Db,
        user_id: str,
        another_user_id: str
    ) -> None:
        database_name = test_db.database_name
        document_id = user_id
        body = {'field1': 'value1', 'field2': 'value2'}

        another_document_id = another_user_id
        another_body = {'fieldA': 'valueA', 'fieldB': 'valueB'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )

        test_db.create_document(document_id= another_document_id, body=another_body)
        test_db.create_document(document_id= document_id, body=body)

        document_info = db.get_document_by_id(
            database_name=database_name,
            document_id=document_id,
        )

        assert document_info
        assert utils.deep_traversal(document_info, '_id') == document_id
        assert utils.deep_traversal(document_info, 'field1') == 'value1'
        assert utils.deep_traversal(document_info, 'field2') == 'value2'
        assert utils.deep_traversal(document_info, 'fieldA') is None
        assert utils.deep_traversal(document_info, 'fieldB') is None

    def test_get_document_by_id__inexistent_document(self, test_db: Db, user_id: str) -> None:
        database_name = test_db.database_name
        document_id = user_id

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        # The document wasn't created, so the `id` doesn't exists on database

        with pytest.raises(httpx.HTTPStatusError, match="Client error '404 Object Not Found'"):
            db.get_document_by_id(
                database_name=database_name,
                document_id=document_id,
            )

    # ----------------------------------------------------------------------------------------------
    #   CouchDB.get_document_fields_by_id() method
    # ----------------------------------------------------------------------------------------------
    def test_get_document_fields_by_id__general_case(
        self,
        test_db: Db,
        user_id: str,
        another_user_id: str
    ) -> None:
        database_name = test_db.database_name
        document_id = user_id
        body = {'field1': 'value1', 'field2': 'value2'}

        another_document_id = another_user_id
        another_body = {'fieldA': 'valueA', 'fieldB': 'valueB'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )

        test_db.create_document(document_id= another_document_id, body=another_body)
        test_db.create_document(document_id= document_id, body=body)

        document_info = db.get_document_fields_by_id(
            database_name=database_name,
            document_id=document_id,
            fields=['_id', *body.keys()],
        )

        assert document_info
        assert utils.deep_traversal(document_info, '_id') == document_id
        assert utils.deep_traversal(document_info, 'field1') == 'value1'
        assert utils.deep_traversal(document_info, 'field2') == 'value2'
        assert utils.deep_traversal(document_info, 'fieldA') is None
        assert utils.deep_traversal(document_info, 'fieldB') is None

    def test_get_document_fields_by_id__all_fields(self, test_db: Db, user_id: str) -> None:
        database_name = test_db.database_name
        document_id = user_id
        body = {'field1': 'value1', 'field2': 'value2'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        test_db.create_document(document_id= document_id, body=body)

        document_info = db.get_document_fields_by_id(
            database_name=database_name,
            document_id=document_id,
        )

        assert document_info
        assert utils.deep_traversal(document_info, '_id') == document_id
        assert utils.deep_traversal(document_info, 'field1') == 'value1'
        assert utils.deep_traversal(document_info, 'field2') == 'value2'

    def test_get_document_fields_by_id__specific_fields(self, test_db: Db, user_id: str) -> None:
        database_name = test_db.database_name
        document_id = user_id
        body = {'field1': 'value1', 'field2': 'value2'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        test_db.create_document(document_id= document_id, body=body)

        document_info = db.get_document_fields_by_id(
            database_name=database_name,
            document_id=document_id,
            fields=['field1']
        )

        assert document_info
        assert utils.deep_traversal(document_info, '_id') is None
        assert utils.deep_traversal(document_info, 'field1') == 'value1'
        assert utils.deep_traversal(document_info, 'field2') is None

    def test_get_document_fields_by_id__inexistent_field(self, test_db: Db, user_id: str) -> None:
        database_name = test_db.database_name
        document_id = user_id
        body = {'field1': 'value1', 'field2': 'value2'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        test_db.create_document(document_id= document_id, body=body)

        document_info = db.get_document_fields_by_id(
            database_name=database_name,
            document_id=document_id,
            fields=['inexistent']
        )

        assert document_info == {}

    def test_get_document_fields_by_id__inexistent_document(
        self,
        test_db: Db,
        user_id: str
    ) -> None:
        database_name = test_db.database_name
        document_id = user_id
        body = {'field1': 'value1', 'field2': 'value2'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        # The document wasn't created, so the `id` doesn't exists on database

        document_info = db.get_document_fields_by_id(
            database_name=database_name,
            document_id=document_id,
            fields=['_id', *body.keys()],
        )

        assert document_info == {}

    # ----------------------------------------------------------------------------------------------
    #   CouchDB.get_document_by_fields() method
    # ----------------------------------------------------------------------------------------------
    def test_get_document_by_fields__general_case(
        self,
        test_db: Db,
        user_id: str,
        another_user_id: str
    ) -> None:
        database_name = test_db.database_name
        main_document_id = user_id
        main_body = {'field1': 'value1', 'field2': 'value2'}

        another_document_id = another_user_id
        another_body = {'fieldA': 'valueA', 'fieldB': 'valueB'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        test_db.create_document(document_id= another_document_id, body=another_body)
        test_db.create_document(document_id= main_document_id, body=main_body)

        fields_dict = {'_id': main_document_id, 'field1': 'value1'}
        document_info = db.get_document_by_fields(
            database_name=database_name,
            fields_dict=fields_dict,
            additional_fields=['field2'],
        )

        assert document_info
        assert utils.deep_traversal(document_info, '_id') == main_document_id
        assert utils.deep_traversal(document_info, 'field1') == 'value1'
        assert utils.deep_traversal(document_info, 'field2') == 'value2'
        assert utils.deep_traversal(document_info, 'fieldA') is None
        assert utils.deep_traversal(document_info, 'fieldB') is None

    def test_get_document_by_fields__specific_fields__no_additional(
        self,
        test_db: Db,
        user_id: str,
    ) -> None:
        database_name = test_db.database_name
        main_document_id = user_id
        main_body = {'field1': 'value1', 'field2': 'value2'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        test_db.create_document(document_id= main_document_id, body=main_body)

        fields_dict = {'_id': main_document_id, 'field2': 'value2'}
        document_info = db.get_document_by_fields(
            database_name=database_name,
            fields_dict=fields_dict,
        )

        assert document_info
        assert utils.deep_traversal(document_info, '_id') == main_document_id
        assert utils.deep_traversal(document_info, 'field1') is None
        assert utils.deep_traversal(document_info, 'field2') == 'value2'

    def test_get_document_by_fields__specific_fields__only_additional(
        self,
        test_db: Db,
        user_id: str,
    ) -> None:
        database_name = test_db.database_name
        main_document_id = user_id
        main_body = {'field1': 'value1', 'field2': 'value2'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        test_db.create_document(document_id= main_document_id, body=main_body)

        fields_dict = {'_id': main_document_id}
        document_info = db.get_document_by_fields(
            database_name=database_name,
            fields_dict=fields_dict,
            additional_fields=['field2'],
        )

        assert document_info
        assert utils.deep_traversal(document_info, '_id') == main_document_id
        assert utils.deep_traversal(document_info, 'field1') is None
        assert utils.deep_traversal(document_info, 'field2') == 'value2'

    def test_get_document_by_fields__inexistent_field(
        self,
        test_db: Db,
        user_id: str,
    ) -> None:
        database_name = test_db.database_name
        main_document_id = user_id
        main_body = {'field1': 'value1', 'field2': 'value2'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        test_db.create_document(document_id= main_document_id, body=main_body)

        fields_dict = {'_id': main_document_id, 'inexistent_field': 'inexistent_value'}
        document_info = db.get_document_by_fields(
            database_name=database_name,
            fields_dict=fields_dict,
        )

        assert document_info == {}

    def test_get_document_by_fields__inexistent_additional_field(
        self,
        test_db: Db,
        user_id: str,
    ) -> None:
        database_name = test_db.database_name
        main_document_id = user_id
        main_body = {'field1': 'value1', 'field2': 'value2'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        test_db.create_document(document_id= main_document_id, body=main_body)

        fields_dict = {'_id': main_document_id, 'field1': 'value1'}
        document_info = db.get_document_by_fields(
            database_name=database_name,
            fields_dict=fields_dict,
            additional_fields=['inexistent_field'],
        )

        assert document_info
        assert utils.deep_traversal(document_info, '_id') == main_document_id
        assert utils.deep_traversal(document_info, 'field1') == 'value1'
        assert utils.deep_traversal(document_info, 'field2') is None
        assert utils.deep_traversal(document_info, 'inexistent_field') is None

    # ----------------------------------------------------------------------------------------------
    #   CouchDB.get_all_document() method
    # ----------------------------------------------------------------------------------------------
    # spell-checker: disable

    def test_get_all_document__general_case(self, test_db: Db) -> None:
        database_name = test_db.database_name

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )

        first_record_id = 'first-record'
        first_record_document = {
            'fielda': 'value1a',
            'fieldb': ['value1b1', 'value1b2'],
            'fieldc': {
                'fieldc1': 'val1c1',
                'fieldc2': 'val1c2',
            },
        }

        second_record_id = 'second-record'
        second_record_document = {
            'fielda': 'value2a',
            'fieldb': ['value2b1', 'value2b2'],
            'fieldc': {
                'fieldc1': 'val2c1',
                'fieldc2': 'val2c2',
            },
        }

        test_db.create_document(document_id= first_record_id, body=first_record_document)
        test_db.create_document(document_id= second_record_id, body=second_record_document)

        documents_data = db.get_all_documents(database_name=database_name)

        assert documents_data
        assert len(documents_data) == 2

        assert utils.deep_traversal(documents_data, 0, 'fielda') == 'value1a'
        assert len(utils.deep_traversal(documents_data, 0, 'fieldb')) == 2
        assert utils.deep_traversal(documents_data, 0, 'fieldb', 0) == 'value1b1'
        assert utils.deep_traversal(documents_data, 0, 'fieldb', 1) == 'value1b2'
        assert utils.deep_traversal(documents_data, 0, 'fieldc', 'fieldc1') == 'val1c1'
        assert utils.deep_traversal(documents_data, 0, 'fieldc', 'fieldc2') == 'val1c2'

        assert utils.deep_traversal(documents_data, 1, 'fielda') == 'value2a'
        assert len(utils.deep_traversal(documents_data, 1, 'fieldb')) == 2
        assert utils.deep_traversal(documents_data, 1, 'fieldb', 0) == 'value2b1'
        assert utils.deep_traversal(documents_data, 1, 'fieldb', 1) == 'value2b2'
        assert utils.deep_traversal(documents_data, 1, 'fieldc', 'fieldc1') == 'val2c1'
        assert utils.deep_traversal(documents_data, 1, 'fieldc', 'fieldc2') == 'val2c2'

    def test_get_all_document__specific_fields(self, test_db: Db) -> None:
        database_name = test_db.database_name

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )

        first_record_id = 'first-record'
        first_record_document = {
            'fielda': 'value1a',
            'fieldb': ['value1b1', 'value1b2'],
            'fieldc': {
                'fieldc1': 'val1c1',
                'fieldc2': 'val1c2',
            },
        }

        second_record_id = 'second-record'
        second_record_document = {
            'fielda': 'value2a',
            'fieldb': ['value2b1', 'value2b2'],
            'fieldc': {
                'fieldc1': 'val2c1',
                'fieldc2': 'val2c2',
            },
        }

        test_db.create_document(document_id= first_record_id, body=first_record_document)
        test_db.create_document(document_id= second_record_id, body=second_record_document)

        documents_data = db.get_all_documents(
            database_name=database_name,
            fields=['fielda', 'fieldc']
        )

        assert documents_data
        assert len(documents_data) == 2

        assert utils.deep_traversal(documents_data, 0, 'fielda') == 'value1a'
        assert utils.deep_traversal(documents_data, 0, 'fieldb') is None
        assert utils.deep_traversal(documents_data, 0, 'fieldc', 'fieldc1') == 'val1c1'
        assert utils.deep_traversal(documents_data, 0, 'fieldc', 'fieldc2') == 'val1c2'

        assert utils.deep_traversal(documents_data, 1, 'fielda') == 'value2a'
        assert utils.deep_traversal(documents_data, 1, 'fieldb') is None
        assert utils.deep_traversal(documents_data, 1, 'fieldc', 'fieldc1') == 'val2c1'
        assert utils.deep_traversal(documents_data, 1, 'fieldc', 'fieldc2') == 'val2c2'

    def test_get_all_document__empty_fields(self, test_db: Db) -> None:
        database_name = test_db.database_name

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )

        first_record_id = 'first-record'
        first_record_document = {
            'fielda': 'value1a',
            'fieldb': ['value1b1', 'value1b2'],
            'fieldc': {
                'fieldc1': 'val1c1',
                'fieldc2': 'val1c2',
            },
        }

        second_record_id = 'second-record'
        second_record_document = {
            'fielda': 'value2a',
            'fieldb': ['value2b1', 'value2b2'],
            'fieldc': {
                'fieldc1': 'val2c1',
                'fieldc2': 'val2c2',
            },
        }

        test_db.create_document(document_id= first_record_id, body=first_record_document)
        test_db.create_document(document_id= second_record_id, body=second_record_document)

        documents_data = db.get_all_documents(database_name=database_name, fields=[])

        assert documents_data
        assert len(documents_data) == 2

        assert utils.deep_traversal(documents_data, 0, 'fielda') == 'value1a'
        assert len(utils.deep_traversal(documents_data, 0, 'fieldb')) == 2
        assert utils.deep_traversal(documents_data, 0, 'fieldb', 0) == 'value1b1'
        assert utils.deep_traversal(documents_data, 0, 'fieldb', 1) == 'value1b2'
        assert utils.deep_traversal(documents_data, 0, 'fieldc', 'fieldc1') == 'val1c1'
        assert utils.deep_traversal(documents_data, 0, 'fieldc', 'fieldc2') == 'val1c2'

        assert utils.deep_traversal(documents_data, 1, 'fielda') == 'value2a'
        assert len(utils.deep_traversal(documents_data, 1, 'fieldb')) == 2
        assert utils.deep_traversal(documents_data, 1, 'fieldb', 0) == 'value2b1'
        assert utils.deep_traversal(documents_data, 1, 'fieldb', 1) == 'value2b2'
        assert utils.deep_traversal(documents_data, 1, 'fieldc', 'fieldc1') == 'val2c1'
        assert utils.deep_traversal(documents_data, 1, 'fieldc', 'fieldc2') == 'val2c2'

    def test_get_all_document__no_documents(self, test_db: Db) -> None:
        database_name = test_db.database_name

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )

        documents_data = db.get_all_documents(database_name=database_name)

        assert documents_data == []

        # spell-checker: enable
    # ----------------------------------------------------------------------------------------------
    #   CouchDB.clean_up_fields() method
    # ----------------------------------------------------------------------------------------------
    def test_clean_up_fields__general_case(self) -> None:
        test_fields = {
            '_id': 'test_id_value',
            '_rev': '1-234567890',
            'field1': 'value1',
            'field2': 'value2',
            'field3': 'value3'
        }

        expected_fields = {
            'field1': 'value1',
            'field2': 'value2',
            'field3': 'value3'
        }

        assert db.clean_up_fields(fields=test_fields) == expected_fields

    def test_clean_up_fields__no_special_fields(self) -> None:
        test_fields = {
            'field1': 'value1',
            'field2': 'value2',
            'field3': 'value3'
        }

        assert db.clean_up_fields(fields=test_fields) == test_fields

    def test_clean_up_fields__only_special_fields(self) -> None:
        test_fields = {
            '_id': 'test_id_value',
            '_rev': '1-234567890',
        }

        expected_fields = {}

        assert db.clean_up_fields(fields=test_fields) == expected_fields

    # ----------------------------------------------------------------------------------------------
    #   CouchDB.update_document_fields() method
    # ----------------------------------------------------------------------------------------------
    def test_update_document_fields__general_case(self)  -> None:
        original_fields = {
            '_id': 'test_id_value',
            '_rev': '1-234567890',
            'field1': 'value1',
            'field2': 'value2',
            'field3': 'value3'
        }
        updated_fields = {'field2': 'value2a'}

        expected_fields = {'field1': 'value1', 'field2': 'value2a', 'field3': 'value3'}

        assert (
            db.update_document_fields(
                original_fields=original_fields,
                updated_fields=updated_fields
            ) == expected_fields
        )

    def test_update_document_fields__additional_fields(self)  -> None:
        original_fields = {
            '_id': 'test_id_value',
            '_rev': '1-234567890',
            'field1': 'value1',
            'field2': 'value2',
            'field3': 'value3'
        }
        updated_fields = {'_id': 'asdfg', 'field2': 'value2a', 'field4': 'value4'}

        expected_fields = {
            'field1': 'value1',
            'field2': 'value2a',
            'field3': 'value3',
            'field4': 'value4'
        }

        assert (
            db.update_document_fields(
                original_fields=original_fields,
                updated_fields=updated_fields
            ) == expected_fields
        )

    # ----------------------------------------------------------------------------------------------
    #   CouchDB.upsert_document() method
    # ----------------------------------------------------------------------------------------------
    def test_upsert_document__insert__general_case(self, test_db: Db, user_id: str) -> None:
        database_name = test_db.database_name
        document_id = user_id
        all_fields = {'field1': 'value1', 'field2': 'value2', 'field3': 'value3'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )

        revision = db.upsert_document(
            database_name=database_name,
            document_id=document_id,
            fields=all_fields
        )

        document_data = test_db.get_document_by_id(document_id=document_id)

        assert document_data
        assert utils.deep_traversal(document_data, '_id') == document_id
        assert utils.deep_traversal(document_data, '_rev') == revision
        assert utils.deep_traversal(document_data, 'field1') == 'value1'
        assert utils.deep_traversal(document_data, 'field2') == 'value2'
        assert utils.deep_traversal(document_data, 'field3') == 'value3'

    def test_upsert_document__insert__no_fields(self, test_db: Db, user_id: str) -> None:
        database_name = test_db.database_name
        document_id = user_id
        all_fields = {}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )

        revision = db.upsert_document(
            database_name=database_name,
            document_id=document_id,
            fields=all_fields
        )

        document_data = test_db.get_document_by_id(document_id=document_id)

        assert document_data
        assert utils.deep_traversal(document_data, '_id') == document_id
        assert utils.deep_traversal(document_data, '_rev') == revision
        assert len(document_data) == 2

    def test_upsert_document__update__general_case(self, test_db: Db, user_id: str) -> None:
        database_name = test_db.database_name
        document_id = user_id
        all_fields = {'field1': 'value1', 'field2': 'value2', 'field3': 'value3'}
        fields_to_change = {'field2': 'value2a'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        test_db.create_document(document_id= document_id, body=all_fields)

        new_revision = db.upsert_document(
            database_name=database_name,
            document_id=document_id,
            fields=fields_to_change
        )

        document_data = test_db.get_document_by_id(document_id=document_id)

        assert document_data
        assert utils.deep_traversal(document_data, '_id') == document_id
        assert utils.deep_traversal(document_data, '_rev') == new_revision
        assert utils.deep_traversal(document_data, 'field1') == 'value1'
        assert utils.deep_traversal(document_data, 'field2') == 'value2a'
        assert utils.deep_traversal(document_data, 'field3') == 'value3'

    def test_upsert_document__update__additional_fields(self, test_db: Db, user_id: str) -> None:
        database_name = test_db.database_name
        document_id = user_id
        all_fields = {'field1': 'value1', 'field2': 'value2', 'field3': 'value3'}
        fields_to_change = {'field2': 'value2a', 'field4': 'value4'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        test_db.create_document(document_id= document_id, body=all_fields)

        new_revision = db.upsert_document(
            database_name=database_name,
            document_id=document_id,
            fields=fields_to_change
        )

        document_data = test_db.get_document_by_id(document_id=document_id)

        assert document_data
        assert utils.deep_traversal(document_data, '_id') == document_id
        assert utils.deep_traversal(document_data, '_rev') == new_revision
        assert utils.deep_traversal(document_data, 'field1') == 'value1'
        assert utils.deep_traversal(document_data, 'field2') == 'value2a'
        assert utils.deep_traversal(document_data, 'field3') == 'value3'
        assert utils.deep_traversal(document_data, 'field4') == 'value4'

    def test_upsert_document__update__fields_unchanged(self, test_db: Db, user_id: str) -> None:
        database_name = test_db.database_name
        document_id = user_id
        all_fields = {'field1': 'value1', 'field2': 'value2', 'field3': 'value3'}
        fields_to_change = {'field2': 'value2'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        test_db.create_document(document_id= document_id, body=all_fields)

        new_revision = db.upsert_document(
            database_name=database_name,
            document_id=document_id,
            fields=fields_to_change
        )

        document_data = test_db.get_document_by_id(document_id=document_id)

        assert document_data
        assert utils.deep_traversal(document_data, '_id') == document_id
        assert utils.deep_traversal(document_data, '_rev') == new_revision
        assert utils.deep_traversal(document_data, 'field1') == 'value1'
        assert utils.deep_traversal(document_data, 'field2') == 'value2'
        assert utils.deep_traversal(document_data, 'field3') == 'value3'

    def test_upsert_document__update__no_fields_to_change(self, test_db: Db, user_id: str) -> None:
        database_name = test_db.database_name
        document_id = user_id
        all_fields = {'field1': 'value1', 'field2': 'value2', 'field3': 'value3'}
        fields_to_change = {}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )
        test_db.create_document(document_id= document_id, body=all_fields)

        new_revision = db.upsert_document(
            database_name=database_name,
            document_id=document_id,
            fields=fields_to_change
        )

        document_data = test_db.get_document_by_id(document_id=document_id)

        assert document_data
        assert utils.deep_traversal(document_data, '_id') == document_id
        assert utils.deep_traversal(document_data, '_rev') == new_revision
        assert utils.deep_traversal(document_data, 'field1') == 'value1'
        assert utils.deep_traversal(document_data, 'field2') == 'value2'
        assert utils.deep_traversal(document_data, 'field3') == 'value3'

    def test_upsert_document__other_errors(
        self,
        test_db: Db,
        user_id: str,
        invalid_db_credentials: DbCredentials
    ) -> None:
        database_name = test_db.database_name
        document_id = user_id
        all_fields = {'field1': 'value1', 'field2': 'value2', 'field3': 'value3'}

        test_db.create()
        test_db.add_permissions()
        test_db.create_indexes(
            indexes=[
                Index(name=f'{database_name}-id-index', fields=['_id'])
            ]
        )

        with pytest.raises(httpx.HTTPStatusError) as excinfo:
            with mock.patch.object(target=db, attribute='app_credentials', new=invalid_db_credentials):
                # db.app_credentials = invalid_db_credentials
                db.upsert_document(
                    database_name=database_name,
                    document_id=document_id,
                    fields=all_fields
                )

        assert excinfo.value.response.status_code == status.HTTP_401_UNAUTHORIZED
        assert excinfo.value.response.json() == {
            'error': 'unauthorized',
            'reason': 'Name or password is incorrect.'
        }
