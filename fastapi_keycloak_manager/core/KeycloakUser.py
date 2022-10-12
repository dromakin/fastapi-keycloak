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
KeycloakUser.py  
  
created by dromakin as 10.10.2022  
Project fastapi-keycloak  
"""

from __future__ import annotations

__author__ = 'dromakin'
__maintainer__ = 'dromakin'
__credits__ = ['dromakin', ]
__copyright__ = "Dromakin, Inc, 2022"
__status__ = 'Development'
__version__ = 20221010

import functools
import json
from json import JSONDecodeError
from typing import Any, Callable, List, Type, Union
from urllib.parse import urlencode

import requests
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import ExpiredSignatureError, JWTError, jwt
from jose.exceptions import JWTClaimsError
from pydantic import BaseModel
from requests import Response

from fastapi_keycloak.exceptions import (
    ConfigureTOTPException,
    KeycloakError,
    MandatoryActionException,
    UpdatePasswordException,
    UpdateProfileException,
    UpdateUserLocaleException,
    UserNotFound,
    VerifyEmailException,
)
from .KeycloakTokenManager import KeycloakTokenManager
from .model import (
    HTTPMethod,
    KeycloakGroup,
    KeycloakIdentityProvider,
    KeycloakRole,
    KeycloakToken,
    KeycloakUser,
    OIDCUser,
)

from .connector import result_or_error, ConnectionManager


class KeycloakUser:

    def __init__(
            self,
            server_url: str,
            client_id: str,
            client_secret: str,
            realm: str,
            callback_url: str,
            timeout: int = 10,
            token_manager: KeycloakTokenManager = None,
            connection_manager: ConnectionManager = None,
    ):
        """FastAPIKeycloak constructor

        Args:
            server_url (str): The URL of the Keycloak server, with `/core` suffix
            client_id (str): The id of the client used for users
            client_secret (str): The client secret
            realm (str): The _realm (name)
            callback_url (str): Callback URL of the instance, used for core flows. Must match at least one `Valid Redirect URIs` of Keycloak and should point to an endpoint that utilizes the authorization_code flow.
            timeout (int): Timeout in seconds to wait for the server
        """
        self._server_url = server_url
        self._realm = realm
        self._client_id = client_id
        self._client_secret = client_secret
        self._callback_url = callback_url
        self._timeout = timeout
        self._tokenManager = token_manager
        self._connectionManager = connection_manager

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
            "Authorization": f"Bearer {self._tokenManager.get_site_token()}",
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
            "_client_id": self._client_id,
            "client_secret": self._client_secret,
            "_username": username,
            "_password": password,
            "grant_type": "_password",
        }
        response = requests.post(url=self.token_url, headers=headers, data=data, timeout=self._timeout)
        if response.status_code == 401:
            raise HTTPException(status_code=401, detail="Invalid user credentials")
        if response.status_code == 400:
            user: KeycloakUser = self.get_user(query=f"_username={username}")
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

    @functools.cached_property
    def user_auth_scheme(self) -> OAuth2PasswordBearer:
        """Returns the core scheme to register the endpoints with swagger

        Returns:
            OAuth2PasswordBearer: Auth scheme for swagger
        """
        return OAuth2PasswordBearer(tokenUrl=self.token_url)

    @functools.cached_property
    def login_url(self):
        """The URL for users to login on the _realm. Also adds the client id and the callback."""
        params = {
            "response_type": "code",
            "_client_id": self._client_id,
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
    def logout_url(self):
        """The logout endpoint URL"""
        return self.open_id_configuration.get("end_session_endpoint")

    @functools.cached_property
    def realm_url(self):
        """The _realm's endpoint URL"""
        return f"{self._server_url}/realms/{self._realm}"

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
        return f"{self._server_url}/admin/realms/{self._realm}"

    @functools.cached_property
    def _open_id(self):
        """The base endpoint for any opendid connect config info"""
        return f"{self.realm_url}/protocol/openid-connect"

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
            url=f"{self.token_url}/.well-known/openid-configuration",
            timeout=self._timeout,
        )
        return response.json()
