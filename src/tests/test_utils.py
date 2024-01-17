# ==================================================================================================
#  Utils module tests
# ==================================================================================================
import bcrypt
import config
import pytest
import string
from jose import ExpiredSignatureError, jwt, JWTError
from pydantic import SecretStr

import utils
from exceptions import InvalidAccessTokenKeyError

class TestUtils:
    # ----------------------------------------------------------------------------------------------
    #   clear_nulls() function
    # ----------------------------------------------------------------------------------------------
    def test_clear_nulls__general_case(self, general_data: dict) -> None:
        expected_data = {'some_key': 'some_value', 'yet_another_key': 123}

        assert utils.clear_nulls(general_data) == expected_data

    def test_clear_nulls__only_null_values(self, general_data: dict) -> None:
        general_data['some_key'] = None
        general_data['yet_another_key'] = None

        expected_data: dict = dict()

        assert utils.clear_nulls(general_data) == expected_data

    def test_clear_nulls__empty_data(self) -> None:
        general_data: dict = dict()
        expected_data: dict = dict()

        assert utils.clear_nulls(general_data) == expected_data

    def test_clear_nulls__no_null_values(self, general_data: dict) -> None:
        general_data['another_key'] = 234.5
        general_data[321] = ''
        expected_data = general_data

        assert utils.clear_nulls(general_data) == expected_data

    # ----------------------------------------------------------------------------------------------
    #   filter_data() function
    # ----------------------------------------------------------------------------------------------
    def test_filter_data__general_case(self, general_data: dict) -> None:
        expected_data = {'some_key': 'some_value', 321: None}

        assert utils.filter_data(data=general_data, keep=['some_key', 321]) == expected_data

    def test_filter_data__inexistent_keep(self, general_data: dict) -> None:
        expected_data = {'some_key': 'some_value', 321: None}

        assert utils.filter_data(
            data=general_data,
             keep=['inexistent', 'some_key', 321]
        ) == expected_data

    def test_filter_data__keep_none(self, general_data: dict) -> None:
        expected_data: dict = {}

        assert utils.filter_data(data=general_data, keep=[]) == expected_data

    def test_filter_data__empty_data(self) -> None:
        expected_data: dict = {}

        assert utils.filter_data(data={}, keep=['some_key', 321]) == expected_data

    # ----------------------------------------------------------------------------------------------
    #   calc_hash() function
    # ----------------------------------------------------------------------------------------------
    def test_calc_hash__general_case(
        self,
        password: SecretStr,
        known_salt: bytes,
        known_hash: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # We need a known salt to be certain about the resulting hash
        monkeypatch.setattr(bcrypt, 'gensalt', lambda: known_salt)

        assert utils.calc_hash(password) == known_hash

    def test_calc_hash__empty_password(
        self,
        known_salt: bytes,
        known_empty_hash: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        password = SecretStr('')

        # We need a known salt to be certain about the resulting hash
        monkeypatch.setattr(bcrypt, 'gensalt', lambda: known_salt)

        assert utils.calc_hash(password) == known_empty_hash

    # ----------------------------------------------------------------------------------------------
    #   check_password() function
    # ----------------------------------------------------------------------------------------------
    def test_check_password__general_case(self) -> None:
        password = SecretStr('A_complex-password#%1234')

        hash_value = utils.calc_hash(password=password)
        assert utils.check_password(password=password, hash_value=hash_value)

    def test_check_password__empty_password(self) -> None:
        password = SecretStr('')

        hash_value = utils.calc_hash(password=password)
        assert utils.check_password(password=password, hash_value=hash_value)

    # ----------------------------------------------------------------------------------------------
    #   create_token() function
    # ----------------------------------------------------------------------------------------------
    def test_create_token__general_case(self) -> None:
        test_payload = {'sub': 'test_subject', 'field1': 'value1', 'field2': 'value2'}
        token = utils.create_token(payload=test_payload, expiration_hours=1.0)

        token_payload = jwt.decode(
            token,
            key=config.ACCESS_TOKEN_SECRET_KEY or '',
            algorithms=[config.TOKEN_ALGORITHM]
        )

        assert utils.deep_traversal(token_payload, 'sub') == 'test_subject'
        assert utils.deep_traversal(token_payload, 'field1') == 'value1'
        assert utils.deep_traversal(token_payload, 'field2') == 'value2'

    def test_create_token__expired_token(self) -> None:
        test_payload = {'sub': 'test_subject', 'field1': 'value1', 'field2': 'value2'}
        # token expired one hour ago.
        token = utils.create_token(payload=test_payload, expiration_hours=-1.0)

        with pytest.raises(ExpiredSignatureError):
            jwt.decode(
                token,
                key=config.ACCESS_TOKEN_SECRET_KEY or '',
                algorithms=[config.TOKEN_ALGORITHM]
            )

    def test_create_token__invalid_token(self) -> None:
        test_payload = {'sub': 'test_subject', 'field1': 'value1', 'field2': 'value2'}
        # Invalid or corrupted token.
        token = (
            utils.create_token(payload=test_payload, expiration_hours=1.0) + 'invalid'
        )

        with pytest.raises(JWTError):
            jwt.decode(
                token,
                key=config.ACCESS_TOKEN_SECRET_KEY or '',
                algorithms=[config.TOKEN_ALGORITHM]
            )

    def test_create_token__no_token_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        test_payload: dict = {}
        monkeypatch.setattr(target=config, name='ACCESS_TOKEN_SECRET_KEY', value=None)
        with pytest.raises(InvalidAccessTokenKeyError):
            utils.create_token(payload=test_payload, expiration_hours=1.0)

    def test_create_token__invalid_token_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        test_payload: dict = {}
        monkeypatch.setattr(target=config, name='ACCESS_TOKEN_SECRET_KEY', value='')
        with pytest.raises(InvalidAccessTokenKeyError):
            utils.create_token(payload=test_payload, expiration_hours=1.0)

    # ----------------------------------------------------------------------------------------------
    #   get_token_payload() function
    # ----------------------------------------------------------------------------------------------
    def test_get_token_payload__general_case(self) -> None:
        test_payload = {'sub': 'test_subject', 'field1': 'value1', 'field2': 'value2'}
        token = utils.create_token(payload=test_payload, expiration_hours=1.0)

        token_payload = utils.get_token_payload(token=token)

        assert utils.deep_traversal(token_payload, 'sub') == 'test_subject'
        assert utils.deep_traversal(token_payload, 'field1') == 'value1'
        assert utils.deep_traversal(token_payload, 'field2') == 'value2'

    def test_get_token_payload__expired_token(self) -> None:
        test_payload = {'sub': 'test_subject', 'field1': 'value1', 'field2': 'value2'}
        # token expired one hour ago.
        token = utils.create_token(payload=test_payload, expiration_hours=-1.0)

        with pytest.raises(ExpiredSignatureError):
            utils.get_token_payload(token=token)

    def test_get_token_payload__invalid_token(self) -> None:
        test_payload = {'sub': 'test_subject', 'field1': 'value1', 'field2': 'value2'}
        # Invalid or corrupted token.
        token = (
            utils.create_token(payload=test_payload, expiration_hours=1.0) + 'invalid'
        )

        with pytest.raises(JWTError):
            utils.get_token_payload(token=token)

    def test_get_token_payload__no_token_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        test_payload = {'sub': 'test_subject', 'field1': 'value1', 'field2': 'value2'}
        token = utils.create_token(payload=test_payload, expiration_hours=1.0)
        monkeypatch.setattr(target=config, name='ACCESS_TOKEN_SECRET_KEY', value=None)

        with pytest.raises(InvalidAccessTokenKeyError):
            utils.get_token_payload(token=token)

    def test_get_token_payload__invalid_token_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        test_payload = {'sub': 'test_subject', 'field1': 'value1', 'field2': 'value2'}
        token = utils.create_token(payload=test_payload, expiration_hours=1.0)
        monkeypatch.setattr(target=config, name='ACCESS_TOKEN_SECRET_KEY', value='')

        with pytest.raises(InvalidAccessTokenKeyError):
            utils.get_token_payload(token=token)

    # ----------------------------------------------------------------------------------------------
    #   deep_traversal() function
    # ----------------------------------------------------------------------------------------------
    def test_deep_traversal__general_case(self, json_data) -> None:
        assert utils.deep_traversal(json_data, 'field0') == 'value0'
        assert utils.deep_traversal(json_data, 'field1') == 123.45
        assert utils.deep_traversal(json_data, 'field2') == ['alpha', 'beta', 456]
        assert utils.deep_traversal(json_data, 'field2', 2) == 456
        assert utils.deep_traversal(json_data, 'field3', 'f3_0') == 'value3_0'
        assert utils.deep_traversal(json_data, 'field3', 'f3_1', 0) == {'field3_1_0': 'value3_1_0'}
        assert utils.deep_traversal(json_data, 'field3', 'f3_1', 0, 'field3_1_0') == 'value3_1_0'
        assert utils.deep_traversal(json_data, 'field3', 'f3_1', 1, 'field3_1_1b') == 'value3_1_1b'
        assert utils.deep_traversal(json_data, 'field4') is None
        assert utils.deep_traversal(json_data, 'field5') == 0.0
        assert utils.deep_traversal(json_data, 'field6') is False

    def test_deep_traversal__inexistent_data(self, json_data) -> None:
        assert utils.deep_traversal(json_data, 0) is None
        assert utils.deep_traversal(json_data, 'inexistent_field') is None
        assert utils.deep_traversal(json_data, 'inexistent_field', 1) is None
        assert utils.deep_traversal(
            json_data,
            'inexistent_field',
            1,
            'another_inexistent_field'
        ) is None

    def test_deep_traversal__partially_inexistent_data(self, json_data) -> None:
        assert utils.deep_traversal(json_data, 99) is None
        assert utils.deep_traversal(json_data, 'field99') is None
        assert utils.deep_traversal(json_data, 'field2', 99) is None
        assert utils.deep_traversal(json_data, 'field3', 'f99') is None
        assert utils.deep_traversal(json_data, 'field3', 'f3_1', 0, 'field3_1_99') is None
        assert utils.deep_traversal(json_data, 'field3', 'f3_1', 1, 'value3_1_1zzz') is None

    def test_deep_traversal__empty_data(self) -> None:
        json_data: dict = dict()

        assert utils.deep_traversal(json_data, 0) is None
        assert utils.deep_traversal(json_data, 'any_field') is None
        assert utils.deep_traversal(json_data, 'any_field', 1) is None
        assert utils.deep_traversal(json_data, 'any_field', 1, 'any_other_field') is None

    def test_deep_traversal__no_data(self) -> None:
        json_data = None

        assert utils.deep_traversal(json_data, 0) is None
        assert utils.deep_traversal(json_data, 'any_field') is None
        assert utils.deep_traversal(json_data, 'any_field', 1) is None
        assert utils.deep_traversal(json_data, 'any_field', 1, 'any_other_field') is None

    # ----------------------------------------------------------------------------------------------
    #   first() function
    # ----------------------------------------------------------------------------------------------
    def test_first__general_case(self) -> None:
        assert utils.first(['alpha', 'beta', 'gamma']) == 'alpha'
        assert utils.first(['gamma', 'beta', 'alpha']) == 'gamma'
        assert utils.first(['beta', 'gamma', 'beta', 'alpha']) == 'beta'
        assert utils.first([123, 'alpha', 'beta', 'gamma']) == 123
        assert utils.first([None, 'alpha', 'beta', 'gamma']) is None
        assert utils.first(['']) == ''

    def test_first__non_list(self) -> None:
        gen = (elem.upper() for elem in ['delta', 'epsilon', 'zeta'])

        assert utils.first(range(5)) == 0
        assert utils.first(range(3, 100)) == 3
        assert utils.first('some_string') == 's'
        assert utils.first(gen) == 'DELTA'

    def test_first__empty_list(self) -> None:
        assert utils.first([]) is None

    def test_first__none(self) -> None:
        assert utils.first(None) is None

    # ----------------------------------------------------------------------------------------------
    #   split_or_empty() function
    # ----------------------------------------------------------------------------------------------
    def test_split_or_empty__general_case(self) -> None:
        assert utils.split_or_empty('alpha#beta#gamma', separator='#') == ['alpha', 'beta', 'gamma']

    def test_split_or_empty__just_one_element(self) -> None:
        assert utils.split_or_empty('alpha', separator='#') == ['alpha']

    def test_split_or_empty__empty_string(self) -> None:
        assert utils.split_or_empty('', separator='#') == []

    def test_split_or_empty__just_separator(self) -> None:
        assert utils.split_or_empty('#', separator='#') == []

    def test_split_or_empty__empty_separator(self) -> None:
        with pytest.raises(ValueError):
            utils.split_or_empty('alpha#beta#gamma', separator='')

    def test_split_or_empty__multi_char_separator(self) -> None:
        assert utils.split_or_empty(
            'alpha#beta!#gamma', separator='#!@'
        ) == ['alpha', 'beta!', 'gamma']


# spell-checker: disable
# Too many random characters.

    # ----------------------------------------------------------------------------------------------
    #   remove_punctuation() function
    # ----------------------------------------------------------------------------------------------
    def test_remove_punctuation__general_case(self) -> None:
        assert utils.remove_punctuation('asd_wqer$%"   09w5!!67*/  123') == 'asdwqer   09w567  123'

    def test_remove_punctuation__maintain_spaces(self) -> None:
        assert utils.remove_punctuation('_$%"   !!*/  ') == '     '
        assert utils.remove_punctuation(12 * ' ') == 12 * ' '

    def test_remove_punctuation__without_punctuation(self) -> None:
        non_punctuation = 'ewwqoirueroi349ur0wqeuj234ng'
        assert utils.remove_punctuation(non_punctuation) == non_punctuation
        assert (
            utils.remove_punctuation(string.ascii_letters + string.digits) ==
            string.ascii_letters + string.digits
        )

    def test_remove_punctuation__only_punctuation(self) -> None:
        assert utils.remove_punctuation('_$%"!!*/') == ''
        assert utils.remove_punctuation(string.punctuation) == ''

    def test_remove_punctuation__empty_string(self) -> None:
        assert utils.remove_punctuation('') == ''


    # ----------------------------------------------------------------------------------------------
    #   remove_unicode_and_accents() function
    # ----------------------------------------------------------------------------------------------
    def test_remove_unicode_and_accents__general_case(self) -> None:
        assert (
            utils.remove_unicode_and_accents('água é ação, AÇÃO É MECÂNICA') ==
            'agua e acao, ACAO E MECANICA'
        )
        assert (
            utils.remove_unicode_and_accents('água é ação 🙂 AÇÃO É MECÂNICA 🔧') ==
            'agua e acao  ACAO E MECANICA '
        )

    def test_remove_unicode_and_accents__maintain_spaces(self) -> None:
        assert (
            utils.remove_unicode_and_accents('água  é  ação, AÇÃO     É MECÂNICA') ==
            'agua  e  acao, ACAO     E MECANICA'
        )
        assert (
            utils.remove_unicode_and_accents('água  é  ação 🙂 AÇÃO      É MECÂNICA 🔧') ==
            'agua  e  acao  ACAO      E MECANICA '
        )

    def test_remove_unicode_and_accents__without_accents_or_unicode(self) -> None:
        without_accents_or_unicode = 'water is action, action is mechanics'
        assert (
            utils.remove_unicode_and_accents(without_accents_or_unicode) ==
            without_accents_or_unicode
        )
        assert (
            utils.remove_unicode_and_accents(string.ascii_letters + string.digits) ==
            string.ascii_letters + string.digits
        )

    def test_remove_unicode_and_accents__accentuation_only(self) -> None:
        only_accents_and_unicode = 'áéçãÇÃÉÂ'
        assert (utils.remove_unicode_and_accents(only_accents_and_unicode) == 'aecaCAEA')

    def test_remove_unicode_and_accents__unicode_only(self) -> None:
        only_accents_and_unicode = '🤩🍆🎀🌽🇧🇷🌎️'
        assert (utils.remove_unicode_and_accents(only_accents_and_unicode) == '')

    def test_remove_unicode_and_accents__empty_string(self) -> None:
        only_accents_and_unicode = ''
        assert (utils.remove_unicode_and_accents(only_accents_and_unicode) == '')

    # ----------------------------------------------------------------------------------------------
    #   slugify() function
    # ----------------------------------------------------------------------------------------------
    def test_slugify__general_case(self) -> None:
        assert (
            utils.slugify('🤩 T,h!îs       i🌽S\t\n a %%G__õo=D     !t*É"st 32🌎️1  ') ==
            'this-is-a-good-test-321'
        )

    def test_slugify__just_accents_and_some_punctuation(self) -> None:
        assert (
            utils.slugify(' Thîs       iS\n a Gõo=D     !t*É"st 321  ') ==
            'this-is-a-good-test-321'
        )

    def test_slugify__only_invalids(self) -> None:
        assert utils.slugify('$🎀_-🌽&%*🇧🇷/') == ''

    def test_slugify__invalids_with_space(self) -> None:
        assert utils.slugify('$🎀_-   🌽&%*\t\n🇧🇷/') == ''

    def test_slugify__only_spaces(self) -> None:
        assert utils.slugify('   \t  \n\n \t') == ''

    def test_slugify__no_spaces(self) -> None:
        assert utils.slugify('$t🎀_=Ê🌽&s%*🇧🇷T/') == 'test'

    def test_slugify__just_one_space(self) -> None:
        assert utils.slugify('$t🎀_=Ê🌽&s%*🇧🇷T /') == 'test'
        assert utils.slugify('$t🎀_=Ê🌽&s%*🇧🇷T/ ') == 'test'
        assert utils.slugify(' $t🎀_=Ê🌽&s%*🇧🇷T/') == 'test'

    def test_slugify__empty_string(self) -> None:
        assert utils.slugify('') == ''

    def test_slugify__separator_on_string(self) -> None:
        assert utils.slugify(
            'this string has the-separator inside it'
        ) == 'this-string-has-the-separator-inside-it'

# spell-checker: enable
