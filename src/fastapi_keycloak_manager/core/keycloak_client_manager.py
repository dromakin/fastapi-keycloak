# -*- coding: utf-8 -*-
#
# The MIT License (MIT)
#
# Copyright (C) 2022 Dmitriy Romakin <dvromakin@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
keycloak_client_manager.py
  
created by dromakin as 08.10.2022  
Project fastapi-keycloak  
"""

from __future__ import annotations

__author__ = 'dromakin'
__maintainer__ = 'dromakin'
__credits__ = ['dromakin', ]
__copyright__ = "Dromakin, Inc, 2022"
__status__ = 'Development'
__version__ = 20221008

import functools
import json
from builtins import isinstance
from typing import Any, List, Union, Callable
from typing import Iterable
from urllib.parse import urlencode

import requests
from requests import Response
from fastapi import status, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

from .keycloak_token_manager import KeycloakTokenManager
from .models import (
    HTTPMethod,
    KeycloakGroup,
    KeycloakIdentityProvider,
    KeycloakRole,
    KeycloakUser,
    KeycloakToken,
    OIDCUser,
)

from .exceptions import (
    raise_error_from_response,
    KeycloakGetError,
    MandatoryActionException,
    UpdatePasswordException,
    UpdateProfileException,
    UpdateUserLocaleException,
    UserNotFound,
    VerifyEmailException,
    ConfigureTOTPException,
)

from .connector import (
    ConnectionManager,
    result_or_error,
    urls_patterns as urls_patterns
)


class KeycloakClientManager:
    PAGE_SIZE = 100

    def __init__(
            self,
            server_url,
            username=None,
            password=None,
            realm_name='master',
            client_id='admin-cli',
            client_secret_key=None,
            verify=True,
            custom_headers=None,
            auto_refresh_token=None,
            callback_url: str = None,
            timeout: int = 10,
            token_manager: KeycloakTokenManager = None,
    ):
        """

        :param server_url: Keycloak server url
        :param username: admin _username
        :param password: admin _password
        :param realm_name: _realm name
        :param client_id: client id
        :param verify: True if want check _connectionManager SSL
        :param client_secret_key: client secret key
        :param custom_headers: dict of custom header to pass to each HTML request
        :param auto_refresh_token: list of methods that allows automatic _site_token refresh. ex: ['get', 'put', 'post', 'delete']
        """
        self._server_url = server_url
        self._username = username
        self._password = password
        self._realm_name = realm_name
        self._client_id = client_id
        self._client_secret_key = client_secret_key
        self._callback_url = callback_url
        self._verify = verify
        self._auto_refresh_token = auto_refresh_token or []
        self._custom_headers = custom_headers
        self._timeout = timeout
        self._tokenManager = token_manager

        headers = dict()
        if custom_headers is not None:
            # merge custom headers to main headers
            headers.update(custom_headers)

        self._connectionManager = ConnectionManager(
            base_url=server_url,
            headers=headers,
            timeout=60,
            verify=verify
        )

        self._site_token = None
        self._api_token = None

    @property
    def server_url(self):
        return self._server_url

    @server_url.setter
    def server_url(self, value):
        self._server_url = value

    @property
    def realm_name(self):
        return self._realm_name

    @realm_name.setter
    def realm_name(self, value):
        self._realm_name = value

    @property
    def connection(self):
        return self._connectionManager

    @connection.setter
    def connection(self, value):
        self._connectionManager = value

    @property
    def client_id(self):
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    @property
    def client_secret_key(self):
        return self._client_secret_key

    @client_secret_key.setter
    def client_secret_key(self, value):
        self._client_secret_key = value

    @property
    def verify(self):
        return self._verify

    @verify.setter
    def verify(self, value):
        self._verify = value

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        self._username = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = value

    # @property
    # def token(self):
    #     return self._token
    #
    # @token.setter
    # def token(self, value):
    #     self._token = value

    @property
    def auto_refresh_token(self):
        return self._auto_refresh_token

    @auto_refresh_token.setter
    def auto_refresh_token(self, value):
        allowed_methods = {'get', 'post', 'put', 'delete'}
        if not isinstance(value, Iterable):
            raise TypeError('Expected a list of strings among {allowed}'.format(allowed=allowed_methods))
        if not all(method in allowed_methods for method in value):
            raise TypeError('Unexpected method in _auto_refresh_token, accepted methods are {allowed}'.format(
                allowed=allowed_methods))

        self._auto_refresh_token = value

    @property
    def custom_headers(self):
        return self._custom_headers

    @custom_headers.setter
    def custom_headers(self, value):
        self._custom_headers = value

    def __fetch_all(self, url, query=None):
        '''Wrapper function to paginate GET requests

        :param url: The url on which the query is executed
        :param query: Existing query parameters (optional)

        :return: Combined results of paginated queries
        '''
        results = []

        # initalize query if it was called with None
        if not query:
            query = {}
        page = 0
        query['max'] = self.PAGE_SIZE

        # fetch until we can
        while True:
            query['first'] = page * self.PAGE_SIZE
            partial_results = raise_error_from_response(
                self.raw_get(url, **query),
                KeycloakGetError)
            if not partial_results:
                break
            results.extend(partial_results)
            page += 1
        return results

    # realm

    def import_realm(self, payload):
        """
        Import a new _realm from a RealmRepresentation. Realm name must be unique.

        RealmRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_realmrepresentation

        :param payload: RealmRepresentation

        :return: RealmRepresentation
        """

        data_raw = self.raw_post(urls_patterns.URL_ADMIN_REALMS, data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def get_realms(self):
        """
        Lists all realms in Keycloak deployment

        :return: realms list
        """
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_REALMS)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_realm(self, payload, skip_exists=False):
        """
        Create a _realm

        RealmRepresentation:
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_realmrepresentation

        :param payload: RealmRepresentation
        :param skip_exists: Skip if Realm already exist.
        :return:  Keycloak server response (RealmRepresentation)
        """

        data_raw = self.raw_post(urls_patterns.URL_ADMIN_REALMS,
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def update_realm(self, realm_name, payload):
        """
        Update a _realm. This wil only update top level attributes and will ignore any user,
        role, or client information in the payload.

        RealmRepresentation:
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_realmrepresentation

        :param realm_name: Realm name (not the _realm id)
        :param payload: RealmRepresentation
        :return: Http response
        """

        params_path = {"realm-name": realm_name}
        data_raw = self.raw_put(urls_patterns.URL_ADMIN_REALM.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def delete_realm(self, realm_name):
        """
        Delete a _realm

        :param realm_name: Realm name (not the _realm id)
        :return: Http response
        """

        params_path = {"realm-name": realm_name}
        data_raw = self.raw_delete(urls_patterns.URL_ADMIN_REALM.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    # provider

    def create_idp(self, payload):
        """
        Create an ID Provider,

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_identityproviderrepresentation

        :param: payload: IdentityProviderRepresentation
        """
        params_path = {"realm-name": self._realm_name}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_IDPS.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def add_mapper_to_idp(self, idp_alias, payload):
        """
        Create an ID Provider,

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_identityprovidermapperrepresentation

        :param: idp_alias: alias for Idp to add mapper in
        :param: payload: IdentityProviderMapperRepresentation
        """
        params_path = {"realm-name": self._realm_name, "idp-alias": idp_alias}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_IDP_MAPPERS.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def get_idps(self):
        """
        Returns a list of ID Providers,

        IdentityProviderRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_identityproviderrepresentation

        :return: array IdentityProviderRepresentation
        """
        params_path = {"realm-name": self._realm_name}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_IDPS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_idp(self, idp_alias):
        """
        Deletes ID Provider,

        :param: idp_alias: idp alias name
        """
        params_path = {"realm-name": self._realm_name, "alias": idp_alias}
        data_raw = self.raw_delete(urls_patterns.URL_ADMIN_IDP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    # users

    def create_user(self, payload):
        """
        Create a new user. Username must be unique

        UserRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_userrepresentation

        :param payload: UserRepresentation

        :return: UserRepresentation
        """
        params_path = {"realm-name": self._realm_name}

        exists = self.get_user_id(username=payload['_username'])

        if exists is not None:
            return str(exists)

        data_raw = self.raw_post(urls_patterns.URL_ADMIN_USERS.format(**params_path),
                                 data=json.dumps(payload))
        raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])
        _last_slash_idx = data_raw.headers['Location'].rindex('/')
        return data_raw.headers['Location'][_last_slash_idx + 1:]

    def users_count(self):
        """
        User counter

        :return: counter
        """
        params_path = {"realm-name": self._realm_name}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_USERS_COUNT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_id(self, username):
        """
        Get internal keycloak user id from _username
        This is required for further actions against this user.

        UserRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_userrepresentation

        :param username: id in UserRepresentation

        :return: user_id
        """

        users = self.get_users(query={"search": username})
        return next((user["id"] for user in users if user["username"] == username), None)

    def get_current_user(self, required_roles: List[str] = None, extra_fields: List[str] = None) -> Callable[
        [OAuth2PasswordBearer], OIDCUser]:
        """Returns the current user based on an access _site_token in the HTTP-header. Optionally verifies roles are possessed
        by the user

        Args:
            required_roles List[str]: List of role names required for this endpoint
            extra_fields List[str]: The names of the additional fields you need that are encoded in JWT

        Returns:
            Callable[OAuth2PasswordBearer, OIDCUser]: Dependency method which returns the decoded JWT content

        Raises:
            ExpiredSignatureError: If the _site_token is expired (exp > datetime.now())
            JWTError: If decoding fails or the signature is invalid
            JWTClaimsError: If any claim is invalid
            HTTPException: If any role required is not contained within the roles of the users
        """

        def current_user(
                token: OAuth2PasswordBearer = Depends(self.user_auth_scheme),
        ) -> OIDCUser:
            """Decodes and verifies a JWT to get the current user

            Args:
                _site_token OAuth2PasswordBearer: Access _site_token in `Authorization` HTTP-header

            Returns:
                OIDCUser: Decoded JWT content

            Raises:
                ExpiredSignatureError: If the _site_token is expired (exp > datetime.now())
                JWTError: If decoding fails or the signature is invalid
                JWTClaimsError: If any claim is invalid
                HTTPException: If any role required is not contained within the roles of the users
            """
            decoded_token = self._tokenManager.decode_token_v1(token=token, audience="account")
            user = OIDCUser.parse_obj(decoded_token)
            if required_roles:
                for role in required_roles:
                    if role not in user.roles:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f'Role "{role}" is required to perform this action',
                        )

            if extra_fields:
                for field in extra_fields:
                    user.extra_fields[field] = decoded_token.get(field, None)

            return user

        return current_user

    @result_or_error(response_model=KeycloakUser)
    def get_user(self, user_id: str = None, query: str = "") -> KeycloakUser:
        """Queries the keycloak API for a specific user either based on its ID or any **native** attribute

        Args:
            user_id (str): The user ID of interest
            query: Query string. e.g. `email=testuser@codespecialist.com` or `_username=codespecialist`

        Returns:
            KeycloakUser: If the user was found

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_token}",
        }

        if user_id is None:
            response = self._connectionManager.make_request(
                url=f"{self.users_url}?{query}",
                method=HTTPMethod.GET,
                headers=headers,
            )
            return KeycloakUser(**response.json()[0])
        else:
            response = self._connectionManager.make_request(
                url=f"{self.users_url}/{user_id}",
                method=HTTPMethod.GET,
                headers=headers,
            )
            if response.status_code == status.HTTP_404_NOT_FOUND:
                raise UserNotFound(
                    status_code=status.HTTP_404_NOT_FOUND,
                    reason=f"User with user_id[{user_id}] was not found"
                )
            return KeycloakUser(**response.json())

    @result_or_error(response_model=KeycloakToken)
    def user_login(self, username: str, password: str) -> KeycloakToken:
        """Models the _password OAuth2 flow. Exchanges _username and _password for an access _site_token. Will raise detailed
        errors if login fails due to requiredActions

        Args:
            username (str): Username used for login
            password (str): Password of the user

        Returns:
            KeycloakToken: If the exchange succeeds

        Raises:
            HTTPException: If the credentials did not match any user
            MandatoryActionException: If the login is not possible due to mandatory actions
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299, != 400, != 401)
            UpdateUserLocaleException: If the credentials we're correct but the has requiredActions of which the first
            one is to update his locale
            ConfigureTOTPException: If the credentials we're correct but the has requiredActions of which the first one
            is to configure TOTP
            VerifyEmailException: If the credentials we're correct but the has requiredActions of which the first one
            is to _verify his email
            UpdatePasswordException: If the credentials we're correct but the has requiredActions of which the first one
            is to update his _password
            UpdateProfileException: If the credentials we're correct but the has requiredActions of which the first one
            is to update his profile

        Notes:
            - To avoid calling this multiple times, you may want to check all requiredActions of the user if it fails
            due to a (sub)instance of an MandatoryActionException
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self._client_id,
            "client_secret_key": self._client_secret,
            "username": username,
            "password": password,
            "grant_type": "password",
        }
        response = requests.post(url=self.token_url, headers=headers, data=data, timeout=self._timeout)
        if response.status_code == 401:
            raise HTTPException(status_code=401, detail="Invalid user credentials")
        if response.status_code == 400:
            user: KeycloakUser = self.get_user(query=f"username={username}")
            if len(user.requiredActions) > 0:
                reason = user.requiredActions[0]
                exception = {
                    "update_user_locale": UpdateUserLocaleException(),
                    "CONFIGURE_TOTP": ConfigureTOTPException(),
                    "VERIFY_EMAIL": VerifyEmailException(),
                    "UPDATE_PASSWORD": UpdatePasswordException(),
                    "UPDATE_PROFILE": UpdateProfileException(),
                }.get(
                    reason,  # Try to return the matching exception
                    # On custom or unknown actions return a MandatoryActionException by default
                    MandatoryActionException(
                        detail=f"This user can't login until the following action has been "
                               f"resolved: {reason}"
                    ),
                )
                raise exception
        return response

    def get_user(self, user_id):
        """
        Get representation of the user

        :param user_id: User id

        UserRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_userrepresentation

        :return: UserRepresentation
        """
        params_path = {"realm-name": self._realm_name, "id": user_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_USER.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_users(self, query=None):
        """
        Return a list of users, filtered according to query parameters

        UserRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_userrepresentation

        :param query: Query parameters (optional)
        :return: users list
        """
        params_path = {"realm-name": self._realm_name}
        return self.__fetch_all(urls_patterns.URL_ADMIN_USERS.format(**params_path), query)

    def get_user_groups(self, user_id):
        """
        Returns a list of groups of which the user is a member

        :param user_id: User id

        :return: user groups list
        """
        params_path = {"realm-name": self._realm_name, "id": user_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_USER_GROUPS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_user(self, user_id, payload):
        """
        Update the user

        :param user_id: User id
        :param payload: UserRepresentation

        :return: Http response
        """
        params_path = {"realm-name": self._realm_name, "id": user_id}
        data_raw = self.raw_put(urls_patterns.URL_ADMIN_USER.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def delete_user(self, user_id):
        """
        Delete the user

        :param user_id: User id

        :return: Http response
        """
        params_path = {"realm-name": self._realm_name, "id": user_id}
        data_raw = self._connectionManager.raw_delete(urls_patterns.URL_ADMIN_USER.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def set_user_password(self, user_id, password, temporary=True):
        """
        Set up a _password for the user. If temporary is True, the user will have to reset
        the temporary _password next time they log in.

        https://www.keycloak.org/docs-api/8.0/rest-api/#_users_resource
        https://www.keycloak.org/docs-api/8.0/rest-api/#_credentialrepresentation

        :param user_id: User id
        :param password: New _password
        :param temporary: True if _password is temporary

        :return:
        """
        payload = {"type": "password", "temporary": temporary, "value": password}
        params_path = {"realm-name": self._realm_name, "id": user_id}
        data_raw = self.raw_put(urls_patterns.URL_ADMIN_RESET_PASSWORD.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def consents_user(self, user_id):
        """
        Get consents granted by the user

        :param user_id: User id

        :return: consents
        """
        params_path = {"realm-name": self._realm_name, "id": user_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_USER_CONSENTS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_user_social_logins(self, user_id):
        """
        Returns a list of federated identities/social logins of which the user has been associated with
        :param user_id: User id
        :return: federated identities list
        """
        params_path = {"realm-name": self._realm_name, "id": user_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_USER_FEDERATED_IDENTITIES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def add_user_social_login(self, user_id, provider_id, provider_userid, provider_username):

        """
        Add a federated identity / social login provider to the user
        :param user_id: User id
        :param provider_id: Social login provider id
        :param provider_userid: userid specified by the provider
        :param provider_username: _username specified by the provider
        :return:
        """
        payload = {"identityProvider": provider_id, "userId": provider_userid, "userName": provider_username}
        params_path = {"realm-name": self._realm_name, "id": user_id, "provider": provider_id}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_USER_FEDERATED_IDENTITY.format(**params_path),
                                 data=json.dumps(payload))

    def send_update_account(self, user_id, payload, client_id=None, lifespan=None, redrealm_url=None):
        """
        Send an update account email to the user. An email contains a
        link the user can click to perform a set of required actions.

        :param user_id: User id
        :param payload: A list of actions for the user to complete
        :param client_id: Client id (optional)
        :param lifespan: Number of seconds after which the generated _site_token expires (optional)
        :param redrealm_url: The redirect url (optional)

        :return:
        """
        params_path = {"realm-name": self._realm_name, "id": user_id}
        params_query = {"client_id": client_id, "lifespan": lifespan, "redrealm_url": redrealm_url}
        data_raw = self.raw_put(urls_patterns.URL_ADMIN_SEND_UPDATE_ACCOUNT.format(**params_path),
                                data=payload, **params_query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def send_verify_email(self, user_id, client_id=None, redrealm_url=None):
        """
        Send a update account email to the user An email contains a
        link the user can click to perform a set of required actions.

        :param user_id: User id
        :param client_id: Client id (optional)
        :param redrealm_url: Redirect url (optional)

        :return:
        """
        params_path = {"realm-name": self._realm_name, "id": user_id}
        params_query = {"client_id": client_id, "redrealm_url": redrealm_url}
        data_raw = self.raw_put(urls_patterns.URL_ADMIN_SEND_VERIFY_EMAIL.format(**params_path),
                                data={}, **params_query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_sessions(self, user_id):
        """
        Get sessions associated with the user

        :param user_id:  id of user

        UserSessionRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_usersessionrepresentation

        :return: UserSessionRepresentation
        """
        params_path = {"realm-name": self._realm_name, "id": user_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_GET_SESSIONS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_server_info(self):
        """
        Get themes, social providers, core providers, and event listeners available on this server

        ServerInfoRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_serverinforepresentation

        :return: ServerInfoRepresentation
        """
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_SERVER_INFO)
        return raise_error_from_response(data_raw, KeycloakGetError)

    # groups

    @result_or_error(response_model=KeycloakGroup, is_list=True)
    def get_all_groups(self) -> List[KeycloakGroup]:
        """Get all base groups of the Keycloak _realm

        Returns:
            List[KeycloakGroup]: All base groups of the _realm

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=self.groups_url, method=HTTPMethod.GET)

    def get_groups(self):
        """
        Returns a list of groups belonging to the _realm

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_grouprepresentation

        :return: array GroupRepresentation
        """
        params_path = {"realm-name": self._realm_name}
        return self.__fetch_all(urls_patterns.URL_ADMIN_GROUPS.format(**params_path))

    @result_or_error(response_model=KeycloakGroup)
    def get_group(self, group_id: str) -> KeycloakGroup or None:
        """Return Group based on group id

        Args:
            group_id (str): Group id to be found

        Returns:
             KeycloakGroup: Keycloak object by id. Or None if the id is invalid

        Notes:
            - The Keycloak RestAPI will only identify GroupRepresentations that
              use name AND id which is the only reason for existence of this function

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.groups_url}/{group_id}",
            method=HTTPMethod.GET,
        )

    def get_group(self, group_id):
        """
        Get group by id. Returns full group details

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_grouprepresentation

        :param group_id: The group id
        :return: Keycloak server response (GroupRepresentation)
        """
        params_path = {"realm-name": self._realm_name, "id": group_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_GROUP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_subgroups(self, group: KeycloakGroup, path: str):
        """Utility function to iterate through nested group structures

        Args:
            group (KeycloakGroup): Group Representation
            path (str): Subgroup path

        Returns:
            KeycloakGroup: Keycloak group representation or none if not exists
        """
        for subgroup in group.subGroups:
            if subgroup.path == path:
                return subgroup
            elif subgroup.subGroups:
                for subgroup in group.subGroups:
                    if subgroups := self.get_subgroups(subgroup, path):
                        return subgroups
        # Went through the tree without hits
        return None

    def get_subgroups(self, group, path):
        """
        Utility function to iterate through nested group structures

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_grouprepresentation

        :param name: group (GroupRepresentation)
        :param path: group path (string)

        :return: Keycloak server response (GroupRepresentation)
        """

        for subgroup in group["subGroups"]:
            if subgroup['path'] == path:
                return subgroup
            elif subgroup["subGroups"]:
                for subgroup in group["subGroups"]:
                    result = self.get_subgroups(subgroup, path)
                    if result:
                        return result
        # went through the tree without hits
        return None

    def get_group_members(self, group_id, **query):
        """
        Get members by group id. Returns group members

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_userrepresentation

        :param group_id: The group id
        :param query: Additional query parameters (see https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_getmembers)
        :return: Keycloak server response (UserRepresentation)
        """
        params_path = {"realm-name": self._realm_name, "id": group_id}
        return self.__fetch_all(urls_patterns.URL_ADMIN_GROUP_MEMBERS.format(**params_path), query)

    @result_or_error(response_model=KeycloakGroup, is_list=True)
    def get_user_groups(self, user_id: str) -> List[KeycloakGroup]:
        """Gets all groups of an user

        Args:
            user_id (str): ID of the user of interest

        Returns:
            List[KeycloakGroup]: All groups possessed by the user

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.users_url}/{user_id}/groups",
            method=HTTPMethod.GET,
        )

    @result_or_error(response_model=KeycloakGroup)
    def get_group_by_path_v1(
            self, path: str, search_in_subgroups=True
    ) -> KeycloakGroup or None:
        """Return Group based on path

        Args:
            path (str): Path that should be looked up
            search_in_subgroups (bool): Whether to search in subgroups

        Returns:
            KeycloakGroup: Full entries stored at Keycloak. Or None if the path not found

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        groups = self.get_all_groups()

        for group in groups:
            if group.path == path:
                return group
            elif search_in_subgroups and group.subGroups:
                for group in group.subGroups:
                    if group.path == path:
                        return group
                    res = self.get_subgroups(group, path)
                    if res is not None:
                        return res

    def get_group_by_path_v2(self, path, search_in_subgroups=False):
        """
        Get group id based on name or path.
        A straight name or path match with a top-level group will return first.
        Subgroups are traversed, the first to match path (or name with path) is returned.

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_grouprepresentation

        :param path: group path
        :param search_in_subgroups: True if want search in the subgroups
        :return: Keycloak server response (GroupRepresentation)
        """

        groups = self.get_groups()

        # TODO: Review this code is necessary
        for group in groups:
            if group['path'] == path:
                return group
            elif search_in_subgroups and group["subGroups"]:
                for group in group["subGroups"]:
                    if group['path'] == path:
                        return group
                    res = self.get_subgroups(group, path)
                    if res != None:
                        return res
        return None

    @result_or_error(response_model=KeycloakGroup)
    def create_group_v1(
            self, group_name: str, parent: Union[KeycloakGroup, str] = None
    ) -> KeycloakGroup:
        """Create a group on the _realm

        Args:
            group_name (str): Name of the new group
            parent (Union[KeycloakGroup, str]): Can contain an instance or object id

        Returns:
            KeycloakGroup: If creation succeeded, else it will return the error

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """

        # If it's an objetc id get an instance of the object
        if isinstance(parent, str):
            parent = self.get_group(parent)

        if parent is not None:
            groups_url = f"{self.groups_url}/{parent.id}/children"
            path = f"{parent.path}/{group_name}"
        else:
            groups_url = self.groups_url
            path = f"/{group_name}"

        response = self._admin_request(
            url=groups_url, data={"name": group_name}, method=HTTPMethod.POST
        )
        if response.status_code == 201:
            return self.get_group_by_path_v2(path=path, search_in_subgroups=True)
        else:
            return response

    def create_group_v2(self, payload, parent=None, skip_exists=False):
        """
        Creates a group in the Realm

        :param payload: GroupRepresentation
        :param parent: parent group's id. Required to create a sub-group.
        :param skip_exists: If true then do not raise an error if it already exists

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_grouprepresentation

        :return: Http response
        """

        if parent is None:
            params_path = {"realm-name": self._realm_name}
            data_raw = self.raw_post(urls_patterns.URL_ADMIN_GROUPS.format(**params_path),
                                     data=json.dumps(payload))
        else:
            params_path = {"realm-name": self._realm_name, "id": parent, }
            data_raw = self.raw_post(urls_patterns.URL_ADMIN_GROUP_CHILD.format(**params_path),
                                     data=json.dumps(payload))

        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    @result_or_error()
    def add_user_group(self, user_id: str, group_id: str) -> dict:
        """Add group to a specific user

        Args:
            user_id (str): ID of the user the group should be added to
            group_id (str): Group to add (id)

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.users_url}/{user_id}/groups/{group_id}", method=HTTPMethod.PUT
        )

    def update_group(self, group_id, payload):
        """
        Update group, ignores subgroups.

        :param group_id: id of group
        :param payload: GroupRepresentation with updated information.

        GroupRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/#_grouprepresentation

        :return: Http response
        """

        params_path = {"realm-name": self._realm_name, "id": group_id}
        data_raw = self.raw_put(urls_patterns.URL_ADMIN_GROUP.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def group_set_permissions(self, group_id, enabled=True):
        """
        Enable/Disable permissions for a group. Cannot delete group if disabled

        :param group_id: id of group
        :param enabled: boolean
        :return: Keycloak server response
        """

        params_path = {"realm-name": self._realm_name, "id": group_id}
        data_raw = self.raw_put(urls_patterns.URL_ADMIN_GROUP_PERMISSIONS.format(**params_path),
                                data=json.dumps({"enabled": enabled}))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def group_user_add(self, user_id, group_id):
        """
        Add user to group (user_id and group_id)

        :param user_id:  id of user
        :param group_id:  id of group to add to
        :return: Keycloak server response
        """

        params_path = {"realm-name": self._realm_name, "id": user_id, "group-id": group_id}
        data_raw = self.raw_put(urls_patterns.URL_ADMIN_USER_GROUP.format(**params_path), data=None)
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def group_user_remove(self, user_id, group_id):
        """
        Remove user from group (user_id and group_id)

        :param user_id:  id of user
        :param group_id:  id of group to remove from
        :return: Keycloak server response
        """

        params_path = {"realm-name": self._realm_name, "id": user_id, "group-id": group_id}
        data_raw = self.raw_delete(urls_patterns.URL_ADMIN_USER_GROUP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    @result_or_error()
    def delete_group_v1(self, group_id: str) -> dict:
        """Deletes a group on the _realm

        Args:
            group_id (str): The group (id) to delte

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.groups_url}/{group_id}",
            method=HTTPMethod.DELETE,
        )

    def delete_group_v2(self, group_id):
        """
        Deletes a group in the Realm

        :param group_id:  id of group to delete
        :return: Keycloak server response
        """

        params_path = {"realm-name": self._realm_name, "id": group_id}
        data_raw = self.raw_delete(urls_patterns.URL_ADMIN_GROUP.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    @result_or_error()
    def remove_user_group(self, user_id: str, group_id: str) -> dict:
        """Remove group from a specific user

        Args:
            user_id str: ID of the user the groups should be removed from
            group_id str: Group to remove (id)

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.users_url}/{user_id}/groups/{group_id}",
            method=HTTPMethod.DELETE,
        )

    def get_clients(self):
        """
        Returns a list of clients belonging to the _realm

        ClientRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation

        :return: Keycloak server response (ClientRepresentation)
        """

        params_path = {"realm-name": self._realm_name}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_CLIENTS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client(self, client_id):
        """
        Get representation of the client

        ClientRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation

        :param client_id:  id of client (not client-id)
        :return: Keycloak server response (ClientRepresentation)
        """

        params_path = {"realm-name": self._realm_name, "id": client_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_CLIENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_id(self, client_name):
        """
        Get internal keycloak client id from client-id.
        This is required for further actions against this client.

        :param client_name: name in ClientRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation
        :return: _client_id (uuid as string)
        """

        clients = self.get_clients()

        for client in clients:
            if client_name == client.get('name') or client_name == client.get('clientId'):
                return client["id"]

        return None

    def get_client_authz_settings(self, client_id):
        """
        Get authorization json from client.

        :param client_id: id in ClientRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation
        :return: Keycloak server response
        """

        params_path = {"realm-name": self._realm_name, "id": client_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_CLIENT_AUTHZ_SETTINGS.format(**params_path))
        return data_raw

    def get_client_authz_resources(self, client_id):
        """
        Get resources from client.

        :param client_id: id in ClientRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation
        :return: Keycloak server response
        """

        params_path = {"realm-name": self._realm_name, "id": client_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_CLIENT_AUTHZ_RESOURCES.format(**params_path))
        return data_raw

    def get_client_service_account_user(self, client_id):
        """
        Get service account user from client.

        :param client_id: id in ClientRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation
        :return: UserRepresentation
        """

        params_path = {"realm-name": self._realm_name, "id": client_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_CLIENT_SERVICE_ACCOUNT_USER.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    @result_or_error(response_model=KeycloakUser, is_list=True)
    def get_all_users(self) -> List[KeycloakUser]:
        """Returns all users of the _realm

        Returns:
            List[KeycloakUser]: All Keycloak users of the _realm

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=self.users_url, method=HTTPMethod.GET)

    @result_or_error(response_model=KeycloakUser)
    def get_user(self, user_id: str = None, query: str = "") -> KeycloakUser:
        """Queries the keycloak API for a specific user either based on its ID or any **native** attribute

        Args:
            user_id (str): The user ID of interest
            query: Query string. e.g. `email=testuser@codespecialist.com` or `_username=codespecialist`

        Returns:
            KeycloakUser: If the user was found

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if user_id is None:
            response = self._admin_request(
                url=f"{self.users_url}?{query}", method=HTTPMethod.GET
            )
            return KeycloakUser(**response.json()[0])
        else:
            response = self._admin_request(
                url=f"{self.users_url}/{user_id}", method=HTTPMethod.GET
            )
            if response.status_code == status.HTTP_404_NOT_FOUND:
                raise UserNotFound(
                    status_code=status.HTTP_404_NOT_FOUND,
                    reason=f"User with user_id[{user_id}] was not found"
                )
            return KeycloakUser(**response.json())

    @result_or_error(response_model=KeycloakUser)
    def create_user(
            self,
            first_name: str,
            last_name: str,
            username: str,
            email: str,
            password: str,
            enabled: bool = True,
            initial_roles: List[str] = None,
            send_email_verification: bool = True,
            attributes: dict[str, Any] = None,
    ) -> KeycloakUser:
        """

        Args:
            first_name (str): The first name of the new user
            last_name (str): The last name of the new user
            username (str): The _username of the new user
            email (str): The email of the new user
            password (str): The _password of the new user
            initial_roles (List[str]): The roles the user should posses. Defaults to `None`
            enabled (bool): True if the user should be able to be used. Defaults to `True`
            send_email_verification (bool): If true, the email verification will be added as an required
                                            action and the email triggered - if the user was created successfully.
                                            Defaults to `True`
            attributes (dict): attributes of new user

        Returns:
            KeycloakUser: If the creation succeeded

        Notes:
            - Also triggers the email verification email

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        data = {
            "email": email,
            "username": username,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": enabled,
            "credentials": [
                {"temporary": False, "type": "password", "value": password}
            ],
            "requiredActions": ["VERIFY_EMAIL" if send_email_verification else None],
            "attributes": attributes,
        }
        response = self._admin_request(
            url=self.users_url, data=data, method=HTTPMethod.POST
        )
        if response.status_code != 201:
            return response
        user = self.get_user(query=f"username={username}")
        if send_email_verification:
            self.send_email_verification(user.id)
        if initial_roles:
            self.add_user_roles(initial_roles, user.id)
            user = self.get_user(user_id=user.id)
        return user

    def create_client(self, payload, skip_exists=False):
        """
        Create a client

        ClientRepresentation: https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation

        :param skip_exists: If true then do not raise an error if client already exists
        :param payload: ClientRepresentation
        :return:  Keycloak server response (UserRepresentation)
        """

        params_path = {"realm-name": self._realm_name}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_CLIENTS.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def update_client(self, client_id, payload):
        """
        Update a client

        :param client_id: Client id
        :param payload: ClientRepresentation

        :return: Http response
        """
        params_path = {"realm-name": self._realm_name, "id": client_id}
        data_raw = self.raw_put(urls_patterns.URL_ADMIN_CLIENT.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    @result_or_error(response_model=KeycloakUser)
    def update_user(self, user: KeycloakUser):
        """Updates a user. Requires the whole object.

        Args:
            user (KeycloakUser): The (new) user object

        Returns:
            KeycloakUser: The updated user

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)

        Notes: - You may alter any aspect of the user object, also the requiredActions for instance. There is no
        explicit function for updating those as it is a user update in essence
        """
        response = self._admin_request(
            url=f"{self.users_url}/{user.id}", data=user.__dict__, method=HTTPMethod.PUT
        )
        if response.status_code == 204:  # Update successful
            return self.get_user(user_id=user.id)
        return response

    @result_or_error()
    def delete_user(self, user_id: str) -> dict:
        """Deletes an user

        Args:
            user_id (str): The user ID of interest

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.users_url}/{user_id}",
            method=HTTPMethod.DELETE
        )

    def delete_client(self, client_id):
        """
        Get representation of the client

        ClientRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_clientrepresentation

        :param client_id: keycloak client id (not oauth client-id)
        :return: Keycloak server response (ClientRepresentation)
        """

        params_path = {"realm-name": self._realm_name, "id": client_id}
        data_raw = self.raw_delete(urls_patterns.URL_ADMIN_CLIENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    @result_or_error()
    def change_password(
            self, user_id: str, new_password: str, temporary: bool = False
    ) -> dict:
        """Exchanges a users' _password.

        Args:
            temporary (bool): If True, the _password must be changed on the first login
            user_id (str): The user ID of interest
            new_password (str): The new _password

        Returns:
            dict: Proxied response payload

        Notes:
            - Possibly should be extended by an old _password check

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        credentials = {
            "temporary": temporary,
            "type": "password",
            "value": new_password,
        }
        return self._admin_request(
            url=f"{self.users_url}/{user_id}/reset-password",
            data=credentials,
            method=HTTPMethod.PUT,
        )

    @result_or_error()
    def send_email_verification(self, user_id: str) -> dict:
        """Sends the email to _verify the email address

        Args:
            user_id (str): The user ID of interest

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.users_url}/{user_id}/send-_verify-email",
            method=HTTPMethod.PUT,
        )

    @result_or_error(response_model=KeycloakIdentityProvider, is_list=True)
    def get_identity_providers(self) -> List[KeycloakIdentityProvider]:
        """Returns all configured identity Providers

        Returns:
            List[KeycloakIdentityProvider]: All configured identity providers

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=self.providers_url, method=HTTPMethod.GET).json()

    def get_client_installation_provider(self, client_id, provider_id):
        """
        Get content for given installation provider

        Related documentation:
        https://www.keycloak.org/docs-api/5.0/rest-api/index.html#_clients_resource

        Possible provider_id list available in the ServerInfoRepresentation#clientInstallations
        https://www.keycloak.org/docs-api/5.0/rest-api/index.html#_serverinforepresentation

        :param client_id: Client id
        :param provider_id: provider id to specify response format
        """

        params_path = {"realm-name": self._realm_name, "id": client_id, "provider-id": provider_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_CLIENT_INSTALLATION_PROVIDER.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[200])

    def get_realm_roles(self):
        """
        Get all roles for the _realm or client

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation

        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self._realm_name}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_REALM_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    @result_or_error(response_model=KeycloakRole, is_list=True)
    def get_roles(self, role_names: List[str]) -> List[Any] | None:
        """Returns full entries of Roles based on role names

        Args:
            role_names List[str]: Roles that should be looked up (names)

        Returns:
             List[KeycloakRole]: Full entries stored at Keycloak. Or None if the list of requested roles is None

        Notes:
            - The Keycloak RestAPI will only identify RoleRepresentations that
              use name AND id which is the only reason for existence of this function

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        if role_names is None:
            return
        roles = self.get_all_roles()
        return list(filter(lambda role: role.name in role_names, roles))

    @result_or_error(response_model=KeycloakRole, is_list=True)
    def get_all_roles(self) -> List[KeycloakRole]:
        """Get all roles of the Keycloak _realm

        Returns:
            List[KeycloakRole]: All roles of the _realm

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(url=self.roles_url, method=HTTPMethod.GET)

    def get_realm_role_members(self, role_name, **query):
        """
        Get role members of _realm by role name.
        :param role_name: Name of the role.
        :param query: Additional Query parameters (see https://www.keycloak.org/docs-api/11.0/rest-api/index.html#_roles_resource)
        :return: Keycloak Server Response (UserRepresentation)
        """
        params_path = {"realm-name": self._realm_name, "role-name": role_name}
        return self.__fetch_all(urls_patterns.URL_ADMIN_REALM_ROLES_MEMBERS.format(**params_path), query)

    @result_or_error(response_model=KeycloakRole, is_list=True)
    def get_client_roles_v1(self, user_id: str) -> List[KeycloakRole]:
        """Gets all roles of a user

        Args:
            user_id (str): ID of the user of interest

        Returns:
            List[KeycloakRole]: All roles possessed by the user

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.users_url}/{user_id}/role-mappings/_realm", method=HTTPMethod.GET
        )

    def get_client_roles_v2(self, client_id):
        """
        Get all roles for the client

        :param client_id: id of client (not client-id)

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation

        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self._realm_name, "id": client_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_CLIENT_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_role(self, client_id, role_name):
        """
        Get client role id by name
        This is required for further actions with this role.

        :param client_id: id of client (not client-id)
        :param role_name: role’s name (not id!)

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation

        :return: role_id
        """
        params_path = {"realm-name": self._realm_name, "id": client_id, "role-name": role_name}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_CLIENT_ROLE.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_role_id(self, client_id, role_name):
        """
        Warning: Deprecated

        Get client role id by name
        This is required for further actions with this role.

        :param client_id: id of client (not client-id)
        :param role_name: role’s name (not id!)

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation

        :return: role_id
        """
        role = self.get_client_role(client_id, role_name)
        return role.get("id")

    @result_or_error()
    def create_client_role_v1(self, roles: List[str], user_id: str) -> dict:
        """Adds roles to a specific user

        Args:
            roles List[str]: Roles to add (name)
            user_id str: ID of the user the roles should be added to

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        keycloak_roles = self.get_roles(roles)
        return self._admin_request(
            url=f"{self.users_url}/{user_id}/role-mappings/_realm",
            data=[role.__dict__ for role in keycloak_roles],
            method=HTTPMethod.POST,
        )

    def create_client_role_v2(self, client_role_id, payload, skip_exists=False):
        """
        Create a client role

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation

        :param client_role_id: id of client (not client-id)
        :param payload: RoleRepresentation
        :param skip_exists: If true then do not raise an error if client role already exists
        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self._realm_name, "id": client_role_id}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_CLIENT_ROLES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    @result_or_error()
    def delete_role(self, role_name: str) -> Response:
        """Deletes a role on the _realm

        Args:
            role_name (str): The role (name) to delte

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        return self._admin_request(
            url=f"{self.roles_url}/{role_name}",
            method=HTTPMethod.DELETE,
        )

    def delete_client_role(self, client_role_id, role_name):
        """
        Delete a client role

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation

        :param client_role_id: id of client (not client-id)
        :param role_name: role’s name (not id!)
        """
        params_path = {"realm-name": self._realm_name, "id": client_role_id, "role-name": role_name}
        data_raw = self.raw_delete(urls_patterns.URL_ADMIN_CLIENT_ROLE.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def assign_client_role(self, user_id, client_id, roles):
        """
        Assign a client role to a user

        :param user_id: id of user
        :param client_id: id of client (not client-id)
        :param roles: roles list or role (use RoleRepresentation)
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self._realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_client_role_members(self, client_id, role_name, **query):
        """
        Get members by client role .
        :param client_id: The client id
        :param role_name: the name of role to be queried.
        :param query: Additional query parameters ( see https://www.keycloak.org/docs-api/11.0/rest-api/index.html#_clients_resource)
        :return: Keycloak server response (UserRepresentation)
        """
        params_path = {"realm-name": self._realm_name, "id": client_id, "role-name": role_name}
        return self.__fetch_all(urls_patterns.URL_ADMIN_CLIENT_ROLE_MEMBERS.format(**params_path), query)

    @result_or_error(response_model=KeycloakRole)
    def create_realm_role_v1(self, role_name: str) -> KeycloakRole:
        """Create a role on the _realm

        Args:
            role_name (str): Name of the new role

        Returns:
            KeycloakRole: If creation succeeded, else it will return the error

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        response = self._admin_request(
            url=self.roles_url, data={"name": role_name}, method=HTTPMethod.POST
        )
        if response.status_code == 201:
            return self.get_roles(role_names=[role_name])[0]
        else:
            return response

    def create_realm_role_v2(self, payload, skip_exists=False):
        """
        Create a new role for the _realm or client

        :param payload: The role (use RoleRepresentation)
        :param skip_exists: If true then do not raise an error if _realm role already exists
        :return Keycloak server response
        """

        params_path = {"realm-name": self._realm_name}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_REALM_ROLES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def get_realm_role(self, role_name):
        """
        Get _realm role by role name
        :param role_name: role's name, not id!

        RoleRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_rolerepresentation
        :return: role_id
        """
        params_path = {"realm-name": self._realm_name, "role-name": role_name}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_realm_role(self, role_name, payload):
        """
        Update a role for the _realm by name
        :param role_name: The name of the role to be updated
        :param payload: The role (use RoleRepresentation)
        :return Keycloak server response
        """

        params_path = {"realm-name": self._realm_name, "role-name": role_name}
        data_raw = self._connectionManager.raw_put(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path),
            data=json.dumps(payload)
        )
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    @result_or_error()
    def remove_user_roles(self, roles: List[str], user_id: str) -> Response:
        """Removes roles from a specific user

        Args:
            roles List[str]: Roles to remove (name)
            user_id str: ID of the user the roles should be removed from

        Returns:
            dict: Proxied response payload

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        keycloak_roles = self.get_roles(roles)
        return self._admin_request(
            url=f"{self.users_url}/{user_id}/role-mappings/_realm",
            data=[role.__dict__ for role in keycloak_roles],
            method=HTTPMethod.DELETE,
        )

    def delete_realm_role(self, role_name):
        """
        Delete a role for the _realm by name
        :param role_name:
        :param payload: The role name {'role-name':'name-of-the-role'}
        :return Keycloak server response
        """

        params_path = {"realm-name": self._realm_name, "role-name": role_name}
        data_raw = self._connectionManager.raw_delete(
            urls_patterns.URL_ADMIN_REALM_ROLES_ROLE_BY_NAME.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def add_composite_realm_roles_to_role(self, role_name, roles):
        """
        Add composite roles to the role

        :param role_name: The name of the role
        :param roles: roles list or role (use RoleRepresentation) to be updated
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self._realm_name, "role-name": role_name}
        data_raw = self.raw_post(
            urls_patterns.URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path),
            data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError,
                                         expected_codes=[204])

    def remove_composite_realm_roles_to_role(self, role_name, roles):
        """
        Remove composite roles from the role

        :param role_name: The name of the role
        :param roles: roles list or role (use RoleRepresentation) to be removed
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self._realm_name, "role-name": role_name}
        data_raw = self.raw_delete(
            urls_patterns.URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path),
            data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError,
                                         expected_codes=[204])

    def get_composite_realm_roles_of_role(self, role_name):
        """
        Get composite roles of the role

        :param role_name: The name of the role
        :return Keycloak server response (array RoleRepresentation)
        """

        params_path = {"realm-name": self._realm_name, "role-name": role_name}
        data_raw = self.raw_get(
            urls_patterns.URL_ADMIN_REALM_ROLES_COMPOSITE_REALM_ROLE.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_realm_roles(self, user_id, client_id, roles):
        """
        Assign _realm roles to a user

        :param user_id: id of user
        :param client_id: id of client containing role (not client-id)
        :param roles: roles list or role (use RoleRepresentation)
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self._realm_name, "id": user_id}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_USER_REALM_ROLES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_realm_roles_of_user(self, user_id):
        """
        Get all _realm roles for a user.

        :param user_id: id of user
        :return: Keycloak server response (array RoleRepresentation)
        """

        params_path = {"realm-name": self._realm_name, "id": user_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_USER_REALM_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_group_realm_roles(self, group_id, roles):
        """
        Assign _realm roles to a group

        :param group_id: id of groupp
        :param roles: roles list or role (use GroupRoleRepresentation)
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self._realm_name, "id": group_id}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def delete_group_realm_roles(self, group_id, roles):
        """
        Delete _realm roles of a group

        :param group_id: id of group
        :param roles: roles list or role (use GroupRoleRepresentation)
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self._realm_name, "id": group_id}
        data_raw = self.raw_delete(urls_patterns.URL_ADMIN_GROUPS_REALM_ROLES.format(**params_path),
                                   data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_group_realm_roles(self, group_id):
        """
        Get all _realm roles for a group.

        :param group_id:
        :param user_id: id of the group
        :return: Keycloak server response (array RoleRepresentation)
        """
        params_path = {"realm-name": self._realm_name, "id": group_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_GET_GROUPS_REALM_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def assign_group_client_roles(self, group_id, client_id, roles):
        """
        Assign client roles to a group

        :param group_id: id of group
        :param client_id: id of client (not client-id)
        :param roles: roles list or role (use GroupRoleRepresentation)
        :return Keycloak server response
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self._realm_name, "id": group_id, "client-id": client_id}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_group_client_roles(self, group_id, client_id):
        """
        Get client roles of a group

        :param group_id: id of group
        :param client_id: id of client (not client-id)
        :return Keycloak server response
        """

        params_path = {"realm-name": self._realm_name, "id": group_id, "client-id": client_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_group_client_roles(self, group_id, client_id, roles):
        """
        Delete client roles of a group

        :param group_id: id of group
        :param client_id: id of client (not client-id)
        :param roles: roles list or role (use GroupRoleRepresentation)
        :return Keycloak server response (array RoleRepresentation)
        """

        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self._realm_name, "id": group_id, "client-id": client_id}
        data_raw = self.raw_delete(urls_patterns.URL_ADMIN_GROUPS_CLIENT_ROLES.format(**params_path),
                                   data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_client_roles_of_user(self, user_id, client_id):
        """
        Get all client roles for a user.

        :param user_id: id of user
        :param client_id: id of client (not client-id)
        :return: Keycloak server response (array RoleRepresentation)
        """
        return self._get_client_roles_of_user(urls_patterns.URL_ADMIN_USER_CLIENT_ROLES, user_id, client_id)

    def get_available_client_roles_of_user(self, user_id, client_id):
        """
        Get available client role-mappings for a user.

        :param user_id: id of user
        :param client_id: id of client (not client-id)
        :return: Keycloak server response (array RoleRepresentation)
        """
        return self._get_client_roles_of_user(urls_patterns.URL_ADMIN_USER_CLIENT_ROLES_AVAILABLE, user_id, client_id)

    def get_composite_client_roles_of_user(self, user_id, client_id):
        """
        Get composite client role-mappings for a user.

        :param user_id: id of user
        :param client_id: id of client (not client-id)
        :return: Keycloak server response (array RoleRepresentation)
        """
        return self._get_client_roles_of_user(urls_patterns.URL_ADMIN_USER_CLIENT_ROLES_COMPOSITE, user_id, client_id)

    def _get_client_roles_of_user(self, client_level_role_mapping_url, user_id, client_id):
        params_path = {"realm-name": self._realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.raw_get(client_level_role_mapping_url.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def delete_client_roles_of_user(self, user_id, client_id, roles):
        """
        Delete client roles from a user.

        :param user_id: id of user
        :param client_id: id of client containing role (not client-id)
        :param roles: roles list or role to delete (use RoleRepresentation)
        :return: Keycloak server response
        """
        payload = roles if isinstance(roles, list) else [roles]
        params_path = {"realm-name": self._realm_name, "id": user_id, "client-id": client_id}
        data_raw = self.raw_delete(urls_patterns.URL_ADMIN_USER_CLIENT_ROLES.format(**params_path),
                                   data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_authentication_flows(self):
        """
        Get authentication flows. Returns all flow details

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationflowrepresentation

        :return: Keycloak server response (AuthenticationFlowRepresentation)
        """
        params_path = {"realm-name": self._realm_name}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_FLOWS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_authentication_flow_for_id(self, flow_id):
        """
        Get one authentication flow by it's id/alias. Returns all flow details

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationflowrepresentation

        :param flow_id: the id of a flow NOT it's alias
        :return: Keycloak server response (AuthenticationFlowRepresentation)
        """
        params_path = {"realm-name": self._realm_name, "flow-id": flow_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_FLOWS_ALIAS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_authentication_flow(self, payload, skip_exists=False):
        """
        Create a new authentication flow

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationflowrepresentation

        :param payload: AuthenticationFlowRepresentation
        :param skip_exists: If true then do not raise an error if authentication flow already exists
        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self._realm_name}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_FLOWS.format(**params_path),
                                 data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def copy_authentication_flow(self, payload, flow_alias):
        """
        Copy existing authentication flow under a new name. The new name is given as 'newName' attribute of the passed payload.

        :param payload: JSON containing 'newName' attribute
        :param flow_alias: the flow alias
        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self._realm_name, "flow-alias": flow_alias}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_FLOWS_COPY.format(**params_path),
                                 data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def get_authentication_flow_executions(self, flow_alias):
        """
        Get authentication flow executions. Returns all execution steps

        :param flow_alias: the flow alias
        :return: Response(json)
        """
        params_path = {"realm-name": self._realm_name, "flow-alias": flow_alias}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_authentication_flow_executions(self, payload, flow_alias):
        """
        Update an authentication flow execution

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationexecutioninforepresentation

        :param payload: AuthenticationExecutionInfoRepresentation
        :param flow_alias: The flow alias
        :return: Keycloak server response
        """

        params_path = {"realm-name": self._realm_name, "flow-alias": flow_alias}
        data_raw = self.raw_put(urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS.format(**params_path),
                                data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def create_authentication_flow_execution(self, payload, flow_alias):
        """
        Create an authentication flow execution

        AuthenticationExecutionInfoRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationexecutioninforepresentation

        :param payload: AuthenticationExecutionInfoRepresentation
        :param flow_alias: The flow alias
        :return: Keycloak server response
        """

        params_path = {"realm-name": self._realm_name, "flow-alias": flow_alias}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS_EXEUCUTION.format(**params_path),
                                 data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def create_authentication_flow_subflow(self, payload, flow_alias, skip_exists=False):
        """
        Create a new sub authentication flow for a given authentication flow

        AuthenticationFlowRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_authenticationflowrepresentation

        :param payload: AuthenticationFlowRepresentation
        :param flow_alias: The flow alias
        :param skip_exists: If true then do not raise an error if authentication flow already exists
        :return: Keycloak server response (RoleRepresentation)
        """

        params_path = {"realm-name": self._realm_name, "flow-alias": flow_alias}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_FLOWS_EXECUTIONS_FLOW.format(**params_path),
                                 data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def sync_users(self, storage_id, action):
        """
        Function to trigger user sync from provider

        :param storage_id: The id of the user storage provider
        :param action: Action can be "triggerFullSync" or "triggerChangedUsersSync"
        :return:
        """
        data = {'action': action}
        params_query = {"action": action}

        params_path = {"realm-name": self._realm_name, "id": storage_id}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_USER_STORAGE.format(**params_path),
                                 data=json.dumps(data), **params_query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_scopes(self):
        """
        Get representation of the client scopes for the _realm where we are connected to
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_getclientscopes

        :return: Keycloak server response Array of (ClientScopeRepresentation)
        """

        params_path = {"realm-name": self._realm_name}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_CLIENT_SCOPES.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_scope(self, client_scope_id):
        """
        Get representation of the client scopes for the _realm where we are connected to
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_getclientscopes

        :param client_scope_id: The id of the client scope
        :return: Keycloak server response (ClientScopeRepresentation)
        """

        params_path = {"realm-name": self._realm_name, "scope-id": client_scope_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_CLIENT_SCOPE.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_client_scope(self, payload, skip_exists=False):
        """
        Create a client scope

        ClientScopeRepresentation: https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_getclientscopes

        :param payload: ClientScopeRepresentation
        :param skip_exists: If true then do not raise an error if client scope already exists
        :return:  Keycloak server response (ClientScopeRepresentation)
        """

        params_path = {"realm-name": self._realm_name}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_CLIENT_SCOPES.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201], skip_exists=skip_exists)

    def add_mapper_to_client_scope(self, client_scope_id, payload):
        """
        Add a mapper to a client scope
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_create_mapper

        :param client_scope_id: The id of the client scope
        :param payload: ProtocolMapperRepresentation
        :return: Keycloak server Response
        """

        params_path = {"realm-name": self._realm_name, "scope-id": client_scope_id}

        data_raw = self.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_ADD_MAPPER.format(**params_path), data=json.dumps(payload))

        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def delete_mapper_from_client_scope(self, client_scope_id, protocol_mppaer_id):
        """
        Delete a mapper from a client scope
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_delete_mapper

        :param protocol_mppaer_id:
        :param client_scope_id: The id of the client scope
        :param payload: ProtocolMapperRepresentation
        :return: Keycloak server Response
        """

        params_path = {"realm-name": self._realm_name, "scope-id": client_scope_id,
                       "protocol-mapper-id": protocol_mppaer_id}

        data_raw = self.raw_delete(
            urls_patterns.URL_ADMIN_CLIENT_SCOPES_MAPPERS.format(**params_path))

        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def add_mapper_to_client(self, client_id, payload):
        """
        Add a mapper to a client
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_create_mapper

        :param client_id: The id of the client
        :param payload: ProtocolMapperRepresentation
        :return: Keycloak server Response
        """

        params_path = {"realm-name": self._realm_name, "id": client_id}

        data_raw = self.raw_post(
            urls_patterns.URL_ADMIN_CLIENT_PROTOCOL_MAPPER.format(**params_path), data=json.dumps(payload))

        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def generate_client_secrets(self, client_id):
        """

        Generate a new secret for the client
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_regeneratesecret

        :param client_id:  id of client (not client-id)
        :return: Keycloak server response (ClientRepresentation)
        """

        params_path = {"realm-name": self._realm_name, "id": client_id}
        data_raw = self.raw_post(urls_patterns.URL_ADMIN_CLIENT_SECRETS.format(**params_path), data=None)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_client_secrets(self, client_id):
        """

        Get representation of the client secrets
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_getclientsecret

        :param client_id:  id of client (not client-id)
        :return: Keycloak server response (ClientRepresentation)
        """

        params_path = {"realm-name": self._realm_name, "id": client_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_CLIENT_SECRETS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_components(self, query=None):
        """
        Return a list of components, filtered according to query parameters

        ComponentRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_componentrepresentation

        :param query: Query parameters (optional)
        :return: components list
        """
        params_path = {"realm-name": self._realm_name}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_COMPONENTS.format(**params_path),
                                data=None, **query)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_component(self, payload):
        """
        Create a new component.

        ComponentRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_componentrepresentation

        :param payload: ComponentRepresentation

        :return: UserRepresentation
        """
        params_path = {"realm-name": self._realm_name}

        data_raw = self.raw_post(urls_patterns.URL_ADMIN_COMPONENTS.format(**params_path),
                                 data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])

    def get_component(self, component_id):
        """
        Get representation of the component

        :param component_id: Component id

        ComponentRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_componentrepresentation

        :return: ComponentRepresentation
        """
        params_path = {"realm-name": self._realm_name, "component-id": component_id}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_COMPONENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def update_component(self, component_id, payload):
        """
        Update the component

        :param component_id: Component id
        :param payload: ComponentRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_componentrepresentation

        :return: Http response
        """
        params_path = {"realm-name": self._realm_name, "component-id": component_id}
        data_raw = self.raw_put(urls_patterns.URL_ADMIN_COMPONENT.format(**params_path),
                                data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def delete_component(self, component_id):
        """
        Delete the component

        :param component_id: Component id

        :return: Http response
        """
        params_path = {"realm-name": self._realm_name, "component-id": component_id}
        data_raw = self.raw_delete(urls_patterns.URL_ADMIN_COMPONENT.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def get_keys(self):
        """
        Return a list of keys, filtered according to query parameters

        KeysMetadataRepresentation
        https://www.keycloak.org/docs-api/8.0/rest-api/index.html#_key_resource

        :return: keys list
        """
        params_path = {"realm-name": self._realm_name}
        data_raw = self.raw_get(urls_patterns.URL_ADMIN_KEYS.format(**params_path),
                                data=None)
        return raise_error_from_response(data_raw, KeycloakGetError)

    # raw methods

    def raw_get(self, *args, **kwargs):
        """
        Calls _connectionManager.raw_get.

        If auto_refresh is set for *get* and *access_token* is expired, it will refresh the _site_token
        and try *get* once more.
        """
        r = self._connectionManager.raw_get(*args, **kwargs)
        if 'get' in self.auto_refresh_token and r.status_code == 401:
            self.refresh_token()
            return self._connectionManager.raw_get(*args, **kwargs)
        return r

    def raw_post(self, *args, **kwargs):
        """
        Calls _connectionManager.raw_post.

        If auto_refresh is set for *post* and *access_token* is expired, it will refresh the _site_token
        and try *post* once more.
        """
        r = self._connectionManager.raw_post(*args, **kwargs)
        if 'post' in self.auto_refresh_token and r.status_code == 401:
            self.refresh_token()
            return self._connectionManager.raw_post(*args, **kwargs)
        return r

    def raw_put(self, *args, **kwargs):
        """
        Calls _connectionManager.raw_put.

        If auto_refresh is set for *put* and *access_token* is expired, it will refresh the _site_token
        and try *put* once more.
        """
        r = self._connectionManager.raw_put(*args, **kwargs)
        if 'put' in self.auto_refresh_token and r.status_code == 401:
            self.refresh_token()
            return self._connectionManager.raw_put(*args, **kwargs)
        return r

    def raw_delete(self, *args, **kwargs):
        """
        Calls _connectionManager.raw_delete.

        If auto_refresh is set for *delete* and *access_token* is expired, it will refresh the _site_token
        and try *delete* once more.
        """
        r = self._connectionManager.raw_delete(*args, **kwargs)
        if 'delete' in self._auto_refresh_token and r.status_code == 401:
            self.refresh_token()
            return self._connectionManager.raw_delete(*args, **kwargs)
        return r

    # token

    def get_api_token(self):
        self.get_token(grant_type=["password"])

    def get_site_token(self):
        self.get_token(grant_type=["client_credentials"])

    def get_token(self, grant_type=None):
        headers = dict()

        if grant_type is None:
            grant_type = ["password"]

        if grant_type is ["password"]:
            self._api_token = self._tokenManager.get_token(
                self._username,
                self._password,
                grant_type=grant_type
            )

            headers = {
                'Authorization': 'Bearer ' + self._api_token.get('access_token'),
                'Content-Type': 'application/json'
            }

        else:
            # grant_type = ["client_credentials"]
            self._site_token = self._tokenManager.get_token(
                self._username,
                self._password,
                grant_type=grant_type
            )

            headers = {
                'Authorization': 'Bearer ' + self._site_token.get('access_token'),
                'Content-Type': 'application/json'
            }

        if self.custom_headers is not None:
            # merge custom headers to main headers
            headers.update(self.custom_headers)

        self._connectionManager = ConnectionManager(
            base_url=self._server_url,
            headers=headers,
            timeout=60,
            verify=self._verify
        )

    def refresh_token(self, grant_type=None):

        if grant_type is None:
            grant_type = ["password"]

        refresh_token = None

        try:
            if grant_type is ["password"]:
                refresh_token = self._api_token.get('refresh_token')
                self._api_token = self._tokenManager.refresh_token(refresh_token)
            else:
                refresh_token = self._site_token.get('refresh_token')
                self._site_token = self._tokenManager.refresh_token(refresh_token)

        except KeycloakGetError as e:
            if e.response_code == 400 and (b'Refresh _site_token expired' in e.response_body or
                                           b'Token is not active' in e.response_body):
                self.get_token(grant_type)
            else:
                raise

        if grant_type is ["password"]:
            self._connectionManager.add_param_headers('Authorization', 'Bearer ' + self._api_token.get('access_token'))
        else:
            self._connectionManager.add_param_headers('Authorization', 'Bearer ' + self._site_token.get('access_token'))

    def _admin_request(
            self,
            url: str,
            method: HTTPMethod,
            data: dict = None,
            content_type: str = "application/json",
            grant_type: str = ["password"],
    ) -> Response:
        """Private method that is the basis for any requests requiring admin access to the api. Will append the
        necessary `Authorization` header

        Args:
            url (str): The URL to be called
            method (HTTPMethod): The HTTP verb to be used
            data (dict): The payload of the requests
            content_type (str): The content type of the request

        Returns:
            Response: Response of Keycloak
        """
        token = None

        if grant_type is ["password"]:
            token = self._api_token
        else:
            token = self._site_token

        headers = {
            "Content-Type": content_type,
            "Authorization": f"Bearer {token}",
        }
        return self._connectionManager.make_request(method=method.name, url=url, data=json.dumps(data), headers=headers)

    @functools.cached_property
    def login_url(self):
        """The URL for users to login on the _realm. Also adds the client id and the callback."""
        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_url": self._callback_url,
        }
        return f"{self.authorization_url}?{urlencode(params)}"

    @functools.cached_property
    def authorization_url(self):
        """The authorization endpoint URL"""
        return self.open_id_configuration.get("authorization_endpoint")

    @functools.cached_property
    def token_url(self):
        """The _site_token endpoint URL"""
        return self.open_id_configuration.get("token_endpoint")

    @functools.cached_property
    def realm_url(self):
        """The _realm's endpoint URL"""
        return f"{self._server_url}/realms/{self._realm_name}"

    @functools.cached_property
    def users_url(self):
        """The users endpoint URL"""
        return self.admin_url(resource="users")

    @functools.cached_property
    def roles_url(self):
        """The roles endpoint URL"""
        return self.admin_url(resource="roles")

    @functools.cached_property
    def groups_url(self):
        """The groups endpoint URL"""
        return self.admin_url(resource="groups")

    @functools.cached_property
    def _admin_url(self):
        """The base endpoint for any admin related action"""
        return f"{self._server_url}/admin/realms/{self._realm_name}"

    @functools.cached_property
    def _open_id(self):
        """The base endpoint for any opendid connect config info"""
        return f"{self._server_url}/protocol/openid-connect"

    @functools.cached_property
    def providers_url(self):
        """The endpoint that returns all configured identity providers"""
        return self.admin_url(resource="identity-provider/instances")

    def admin_url(self, resource: str):
        """Returns a admin resource URL"""
        return f"{self._admin_url}/{resource}"

    def open_id(self, resource: str):
        """Returns a openip connect resource URL"""
        return f"{self._open_id}/{resource}"

    @functools.cached_property
    def open_id_configuration(self) -> dict:
        """Returns Keycloaks Open ID Connect configuration

        Returns:
            dict: Open ID Configuration
        """
        response = requests.get(
            url=f"{self.realm_url}/.well-known/openid-configuration",
            timeout=self._timeout,
        )
        return response.json()

    @functools.cached_property
    def user_auth_scheme(self) -> OAuth2PasswordBearer:
        """Returns the core scheme to register the endpoints with swagger

        Returns:
            OAuth2PasswordBearer: Auth scheme for swagger
        """
        return OAuth2PasswordBearer(tokenUrl=self.token_url)
