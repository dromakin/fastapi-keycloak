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
keycloak_token_manager.py
  
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
from json import JSONDecodeError

import requests
from fastapi.security import OAuth2PasswordBearer
from jose import ExpiredSignatureError, JWTError, jwt
from jose.exceptions import JWTClaimsError
from requests import Response

from fastapi_keycloak_manager.core.models.model import (
    HTTPMethod,
    KeycloakToken,
)
from fastapi_keycloak_manager.core.connector import ConnectionManager
from fastapi_keycloak_manager.core.connector import result_or_error
from fastapi_keycloak_manager.core.exceptions import KeycloakError, KeycloakGetError, KeycloakRPTNotFound, \
    KeycloakDeprecationError, raise_error_from_response, KeycloakInvalidTokenError
from fastapi_keycloak_manager.core.connector.urls_patterns import (
    URL_TOKEN,
    URL_LOGOUT,
    URL_CERTS,
    URL_ENTITLEMENT,
    URL_INTROSPECT, URL_REALM, URL_WELL_KNOWN, URL_AUTH,
)


# Class for User and Admin
class KeycloakTokenManager:
    def __init__(
            self,
            server_url: str,
            callback_url: str,
            client_id: str,
            client_secret_key: str,
            realm_name: str,
            timeout: int = 10,
            verify: bool = True,
            custom_headers: dict = None,
    ):
        """FastAPIKeycloak constructor

        :param server_url: The URL of the Keycloak server, with `/core` suffix
        :param callback_url: Callback URL of the instance, used for core flows
        :param client_id: The id of the client used for users
        :param client_secret_key: The client secret
        :param realm_name: The _realm (name)
        :param timeout: Timeout in seconds to wait for the server
        :param verify: True if want check connection SSL
        :param custom_headers: dict of custom header to pass to each HTML request
        """
        self._server_url = server_url
        self._realm_name = realm_name
        self._client_id = client_id
        self._client_secret_key = client_secret_key
        self._callback_url = callback_url
        self._timeout = timeout

        self._site_token = None
        self._api_token = None

        headers = dict()
        if custom_headers is not None:
            # merge custom headers to main headers
            headers.update(custom_headers)

        self._connection = ConnectionManager(base_url=server_url,
                                             headers=headers,
                                             timeout=60,
                                             verify=verify)

    @property
    def connection(self):
        return self._connection

    @connection.setter
    def connection(self, value):
        self._connection = value

    # TOKEN MANAGE

    @functools.cached_property
    def public_key_v1(self) -> str:
        """Returns the Keycloak public key

        Returns:
            str: Public key for JWT decoding
        """
        response = requests.get(url=self.realm_url, timeout=self._timeout)
        public_key = response.json()["public_key"]
        return f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"

    def public_key_v2(self):
        """
        The public key is exposed by the _realm page directly.

        :return:
        """
        params_path = {"realm-name": self._realm_name}
        data_raw = self.connection.raw_get(URL_REALM.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)['public_key']

    def decode_token_v1(
            self, token: str, options: dict = None, audience: str = None
    ) -> dict:
        """Decodes a token, verifies the signature by using Keycloaks public key. Optionally verifying the audience

        Args:
            token (str):
            options (dict):
            audience (str): Name of the audience, must match the audience given in the _site_token

        Returns:
            dict: Decoded JWT

        Raises:
            ExpiredSignatureError: If the _site_token is expired (exp > datetime.now())
            JWTError: If decoding fails or the signature is invalid
            JWTClaimsError: If any claim is invalid
        """
        if options is None:
            options = {
                "verify_signature": True,
                "verify_aud": audience is not None,
                "verify_exp": True,
            }
        return jwt.decode(
            token=token, key=self.public_key_v1, options=options, audience=audience
        )

    def decode_token_v2(self, token, key, algorithms=['RS256'], **kwargs):
        """
        A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data
        structure that represents a cryptographic key.  This specification
        also defines a JWK Set JSON data structure that represents a set of
        JWKs.  Cryptographic algorithms and identifiers for use with this
        specification are described in the separate JSON Web Algorithms (JWA)
        specification and IANA registries established by that specification.

        https://tools.ietf.org/html/rfc7517

        :param token:
        :param key:
        :param algorithms:
        :return:
        """

        return jwt.decode(token, key, algorithms=algorithms,
                          audience=self._client_id, **kwargs)

    def token_info(self, token, method_token_info, **kwargs):
        """

        :param token:
        :param method_token_info:
        :param kwargs:
        :return:
        """
        if method_token_info == 'introspect':
            token_info = self.introspect(token)
        else:
            token_info = self.decode_token_v2(token, **kwargs)

        return token_info

    def token_is_valid(self, token: str, audience: str = None) -> bool:
        """Validates an access _site_token, optionally also its audience

        Args:
            token (str): The _site_token to be verified
            audience (str): Optional audience. Will be checked if provided

        Returns:
            bool: True if the _site_token is valid
        """
        try:
            self.decode_token_v1(token=token, audience=audience)
            return True
        except (ExpiredSignatureError, JWTError, JWTClaimsError):
            return False

    # SITE TOKEN

    @property
    def site_token(self):
        if self.token_is_valid(token=self._site_token):
            return self._site_token
        self.get_site_token()
        return self._site_token

    @site_token.setter
    def site_token(self, value: str):
        """Setter for the _site_token

        Args:
            value (str): An access Token

        Returns:
            None: Inplace method, updates the _site_token
        """
        decoded_token = self.decode_token_v1(token=value)

        r = decoded_token.get("resource_access", None)

        if r is not None:
            if not decoded_token.get("resource_access").get(
                    "realm-management"
            ) or not decoded_token.get("resource_access").get("account"):
                raise AssertionError(
                    f"""The access required was not contained in the access _site_token for the `{self._client_id}`.
                    Possibly a Keycloak misconfiguration. Check if the {self._client_id} client has `Full Scope Allowed`
                    and that the `Service Account Roles` contain all roles from `account` and `realm_management`"""
                )
        else:
            raise AssertionError(
                f"""The access required was not contained in the access _site_token for the `{self._client_id}`.
                Possibly a Keycloak misconfiguration. Check if the {self._client_id} client has `Full Scope Allowed`
                and that the `Service Account Roles` contain all roles from `account` and `realm_management`"""
            )

        self._site_token = value

    def get_site_token(self) -> None:
        """Exchanges client credentials for an access _site_token.

        Returns:
            None: Inplace method that updated the class attribute `_site_token`

        Raises:
            KeycloakError: If fetching an access _site_token fails,
            or the response does not contain an access_token at all

        Notes:
            - Is executed on startup and may be executed again if the _site_token validation fails
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self._client_id,
            "client_secret": self._client_secret_key,
            "grant_type": "client_credentials",
        }
        response = requests.post(url=self.token_url, headers=headers, data=data, timeout=self._timeout)
        try:
            self._site_token = response.json()["access_token"]
        except JSONDecodeError as e:
            raise KeycloakError(
                error_message=response.content.decode("utf-8"),
                response_code=response.status_code,
            ) from e

        except KeyError as e:
            raise KeycloakError(
                error_message=f"The response did not contain an access_token: {response.json()}",
                response_code=403,
            ) from e

    @result_or_error(response_model=KeycloakToken)
    def exchange_authorization_code(
            self, session_state: str, code: str
    ) -> KeycloakToken:
        """Models the authorization code OAuth2 flow. Opening the URL provided by `login_uri` will result in a
        callback to the configured callback URL. The callback will also create a session_state and code query
        parameter that can be exchanged for an access token.

        Args:
            session_state (str): Salt to reduce the risk of successful attacks
            code (str): The authorization code

        Returns:
            KeycloakToken: If the exchange succeeds

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "client_id": self._client_id,
            "client_secret": self._client_secret_key,
            "code": code,
            "session_state": session_state,
            "grant_type": "authorization_code",
            "redirect_url": self._callback_url,
        }
        return requests.post(url=self.token_url, headers=headers, data=data, timeout=self._timeout)

    # API TOKEN

    @property
    def api_token(self):
        if self.token_is_valid(token=self._api_token):
            return self._api_token
        raise KeycloakInvalidTokenError("Token is not valid")

    @api_token.setter
    def api_token(self, value: str):
        """Setter for the _site_token

        Args:
            value (str): An access Token

        Returns:
            None: Inplace method, updates the _site_token
        """
        decoded_token = self.decode_token_v1(token=value)

        r = decoded_token.get("resource_access", None)

        if r is not None:
            if not decoded_token.get("resource_access").get(
                    "realm-management"
            ) or not decoded_token.get("resource_access").get("account"):
                raise AssertionError(
                    f"""The access required was not contained in the access _site_token for the `{self._client_id}`.
                    Possibly a Keycloak misconfiguration. Check if the {self._client_id} client has `Full Scope Allowed`
                    and that the `Service Account Roles` contain all roles from `account` and `realm_management`"""
                )
        else:
            raise AssertionError(
                f"""The access required was not contained in the access _site_token for the `{self._client_id}`.
                Possibly a Keycloak misconfiguration. Check if the {self._client_id} client has `Full Scope Allowed`
                and that the `Service Account Roles` contain all roles from `account` and `realm_management`"""
            )

        self._site_token = value

    # universal method that can used for get site token too
    def get_token(self, username="", password="", grant_type=None, code="", redirect_uri="", totp=None, **extra):
        """
        The token endpoint is used to obtain tokens. Tokens can either be obtained by
        exchanging an authorization code or by supplying credentials directly depending on
        what flow is used. The token endpoint is also used to obtain new access tokens
        when they expire.

        http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

        :param username:
        :param password:
        :param grant_type:
        :param code:
        :param redirect_uri
        :param totp
        :return:
        """
        if grant_type is None:
            grant_type = ["password"]

        params_path = {"realm-name": self._realm_name}
        payload = {"username": username, "password": password,
                   "client_id": self._client_id, "grant_type": grant_type,
                   "code": code, "redirect_uri": redirect_uri}
        if payload:
            payload.update(extra)

        if totp:
            payload["totp"] = totp

        payload = self._add_secret_key(payload)
        data_raw = self.connection.raw_post(URL_TOKEN.format(**params_path),
                                            data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_api_token(self, username="", password="", code="", redirect_uri="", totp=None, **extra):
        return self.get_token(
            username=username,
            password=password,
            grant_type=["password"],
            code=code,
            redirect_uri=redirect_uri,
            totp=totp,
            **extra,
        )

    # REFRASH TOKEN

    def refresh_token(self, refresh_token, grant_type=None):
        """
        The refresh_token endpoint is used to obtain tokens. Tokens can either be obtained by
        exchanging an authorization code or by supplying credentials directly depending on
        what flow is used. The refresh_token endpoint is also used to obtain new access tokens
        when they expire.

        http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint

        :param refresh_token:
        :param grant_type:
        :return:
        """
        if grant_type is None:
            grant_type = ["refresh_token"]

        params_path = {"realm-name": self._realm_name}
        payload = {"client_id": self._client_id, "grant_type": grant_type, "refresh_token": refresh_token}
        payload = self._add_secret_key(payload)
        data_raw = self._connection.raw_post(URL_TOKEN.format(**params_path), data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError)

    # RPT

    def entitlement(self, token, resource_server_id):
        """
        Client applications can use a specific endpoint to obtain a special security token
        called a requesting party token (RPT). This token consists of all the entitlements
        (or permissions) for a user as a result of the evaluation of the permissions and authorization
        policies associated with the resources being requested. With an RPT, client applications can
        gain access to protected resources at the resource server.

        :return:
        """
        self._connection.add_param_headers("Authorization", "Bearer " + token)
        params_path = {"realm-name": self._realm_name, "resource-server-id": resource_server_id}
        data_raw = self._connection.raw_get(URL_ENTITLEMENT.format(**params_path))

        if data_raw.status_code == 404:
            return raise_error_from_response(data_raw, KeycloakDeprecationError)

        return raise_error_from_response(data_raw, KeycloakGetError)

    def introspect(self, token, rpt=None, token_type_hint=None):
        """
        The introspection endpoint is used to retrieve the active state of a token. It is can only be
        invoked by confidential clients.

        https://tools.ietf.org/html/rfc7662

        :param token:
        :param rpt:
        :param token_type_hint:

        :return:
        """
        params_path = {"realm-name": self._realm_name}

        payload = {"client_id": self._client_id, "token": token}

        if token_type_hint == 'requesting_party_token':
            if rpt:
                payload.update({"site_token": rpt, "token_type_hint": token_type_hint})
                self._connection.add_param_headers("Authorization", "Bearer " + token)
            else:
                raise KeycloakRPTNotFound("Can't found RPT.")

        payload = self._add_secret_key(payload)

        data_raw = self._connection.raw_post(
            URL_INTROSPECT.format(**params_path),
            data=payload
        )

        return raise_error_from_response(data_raw, KeycloakGetError)

    # OTHER

    def auth_url(self, redirect_uri):
        """

        http://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint

        :return:
        """
        params_path = {"authorization-endpoint": self.well_know()['authorization_endpoint'],
                       "client-id": self._client_id,
                       "redirect-uri": redirect_uri}
        return URL_AUTH.format(**params_path)

    # Requesting OAuth Authorization Code
    def get_auth_code(self, redirect_uri):
        self._connection.raw_get(self.auth_url(redirect_uri))

    def well_know(self):
        """ The most important endpoint to understand is the well-known configuration
            endpoint. It lists endpoints and other configuration options relevant to
            the OpenID Connect implementation in Keycloak.

            :return It lists endpoints and other configuration options relevant.
        """

        params_path = {"realm-name": self._realm_name}
        data_raw = self._connection.raw_get(URL_WELL_KNOWN.format(**params_path))

        return raise_error_from_response(data_raw, KeycloakGetError)

    def logout(self, refresh_token):
        """
        The logout endpoint logs out the authenticated user.
        :param refresh_token:
        :return:
        """
        params_path = {"realm-name": self._realm_name}
        payload = {"client_id": self._client_id, "refresh_token": refresh_token}

        payload = self._add_secret_key(payload)
        data_raw = self.connection.raw_post(URL_LOGOUT.format(**params_path),
                                            data=payload)

        return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[204])

    def certs(self):
        """
        The certificate endpoint returns the public keys enabled by the _realm, encoded as a
        JSON Web Key (JWK). Depending on the _realm settings there can be one or more keys enabled
        for verifying tokens.

        https://tools.ietf.org/html/rfc7517

        :return:
        """
        params_path = {"realm-name": self._realm_name}
        data_raw = self.connection.raw_get(URL_CERTS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def proxy(
            self,
            relative_path: str,
            method: HTTPMethod,
            additional_headers: dict = None,
            payload: dict = None,
    ) -> Response:
        """Proxies a request to Keycloak and automatically adds the required Authorization header. Should not be
        exposed under any circumstances. Grants full API admin access.

        Args:

            relative_path (str): The relative path of the request.
            Requests will be sent to: `[_server_url]/[relative_path]`
            method (HTTPMethod): The HTTP-verb to be used
            additional_headers (dict): Optional headers besides the Authorization to add to the request
            payload (dict): Optional payload to send

        Returns:
            Response: Proxied response

        Raises:
            KeycloakError: If the resulting response is not a successful HTTP-Code (>299)
        """
        headers = {"Authorization": f"Bearer {self._site_token}"}
        if additional_headers is not None:
            headers = {**headers, **additional_headers}

        return requests.request(
            method=method.name,
            url=f"{self._server_url}{relative_path}",
            data=json.dumps(payload),
            headers=headers,
            timeout=self._timeout,
        )

    def _add_secret_key(self, payload):
        """
        Add secret key if exist.

        :param payload:
        :return:
        """
        if self._client_secret_key:
            payload.update({"client_secret": self._client_secret_key})

        return payload

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
        return f"{self._server_url}/realms/{self._realm_name}"

    @functools.cached_property
    def get_auth_scheme(self) -> OAuth2PasswordBearer:
        """Returns the core scheme to register the endpoints with swagger

        Returns:
            OAuth2PasswordBearer: Auth scheme for swagger
        """
        return OAuth2PasswordBearer(tokenUrl=self.token_url)

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
