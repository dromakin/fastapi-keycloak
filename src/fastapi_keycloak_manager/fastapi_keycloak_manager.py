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
fastapi_keycloak_manager.py
  
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

from fastapi import FastAPI
from fastapi.security import OAuth2PasswordBearer, OAuth2AuthorizationCodeBearer

from core import (
    KeycloakClientManager,
    KeycloakTokenManager,
    ConnectionManager,
    URL_TOKEN
)


class FastAPIKeycloakManager:

    def __init__(
            self,
            server_url,
            username=None,
            password=None,
            realm_name='master',
            client_id='admin-cli',
            client_secret_key=None,
            admin_client_id: str = "admin-cli",
            admin_client_secret: str = None,
            verify=True,
            custom_headers=None,
            auto_refresh_token=None,
            callback_url: str = None,
            timeout: int = 10,

    ):
        """FastAPIKeycloakManager

        Args:
            server_url (str): The URL of the Keycloak server, with `/core` suffix
            client_id (str): The id of the client used for users
            client_secret_key (str): The client secret
            realm (str): The _realm (name)
            admin_client_id (str): The id for the admin client, defaults to 'admin-cli'
            admin_client_secret (str): Secret for the `admin-cli` client
            callback_uri (str): Callback URL of the instance, used for core flows. Must match at least one
            `Valid Redirect URIs` of Keycloak and should point to an endpoint that utilizes the authorization_code flow.
            timeout (int): Timeout in seconds to wait for the server
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
        self._admin_client_id = admin_client_id
        self._admin_client_secret = admin_client_secret

        self.token_manager = KeycloakTokenManager(
            server_url=server_url,
            callback_url=callback_url,
            client_id=client_id,
            client_secret_key=client_secret_key,
            realm_name=realm_name,
            timeout=timeout,
            verify=verify,
            custom_headers=custom_headers,
        )

        headers = dict()
        if custom_headers is not None:
            # merge custom headers to main headers
            headers.update(custom_headers)

        self.connection_manager = ConnectionManager(
            base_url=server_url,
            headers=headers,
            timeout=60,
            verify=verify
        )

        self._user_client_manager = KeycloakClientManager(
            server_url=server_url,
            username=username,
            password=password,
            realm_name=realm_name,
            client_id=client_id,
            client_secret_key=client_secret_key,
            verify=verify,
            custom_headers=custom_headers,
            auto_refresh_token=auto_refresh_token,
            callback_url=callback_url,
            timeout=timeout,
            token_manager=self.token_manager
        )

        self._admin_client_manager = KeycloakClientManager(
            server_url=server_url,
            username=username,
            password=password,
            realm_name=realm_name,
            client_id=admin_client_id,
            client_secret_key=admin_client_secret,
            verify=verify,
            custom_headers=custom_headers,
            auto_refresh_token=auto_refresh_token,
            callback_url=callback_url,
            timeout=timeout,
            token_manager=self.token_manager
        )

    @property
    def admin_client(self):
        return self._admin_client_manager

    @property
    def user_client(self):
        return self._user_client_manager

    def add_swagger_config(self, app: FastAPI):
        """Adds the client id and secret securely to the swagger ui.
        Enabling Swagger ui users to perform actions they usually need the client credentials, without exposing them.

        Args:
            app (FastAPI): Optional FastAPI app to add the config to swagger

        Returns:
            None: Inplace method
        """
        app.swagger_ui_init_oauth = {
            "usePkceWithAuthorizationCodeGrant": True,
            "clientId": self._admin_client_id,
            "clientSecret": self._admin_client_secret,
        }

    @functools.cached_property
    def user_auth_scheme(self) -> OAuth2PasswordBearer:
        """Returns the core scheme to register the endpoints with swagger

        Returns:
            OAuth2PasswordBearer: Auth scheme for swagger
        """
        return OAuth2PasswordBearer(tokenUrl=self.token_manager.token_url)

    def user_auth_scheme_v2(self) -> OAuth2AuthorizationCodeBearer:
        """Returns the core scheme to register the endpoints with swagger

        Returns:
            OAuth2AuthorizationCodeBearer: Auth scheme for swagger
        """
        params_path = {"realm-name": self._realm_name}
        return OAuth2AuthorizationCodeBearer(
            authorizationUrl=self._admin_client_manager.authorization_url,
            tokenUrl=self.token_manager.token_url,
            refreshUrl=URL_TOKEN.format(**params_path),
        )
