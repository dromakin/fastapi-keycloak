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
KeycloakOpenIDManager.py  
  
created by dromakin as 09.10.2022  
Project fastapi-keycloak  
"""

__author__ = 'dromakin'
__maintainer__ = 'dromakin'
__credits__ = ['dromakin', ]
__copyright__ = "Dromakin, Inc, 2022"
__status__ = 'Development'
__version__ = 20221009

import functools

import requests

from .auth import Authorization
from .connector import ConnectionManager
from .exceptions import raise_error_from_response, KeycloakGetError
from .urls_patterns import (
    URL_REALM,
    URL_AUTH,
    URL_WELL_KNOWN,
    URL_CERTS
)


class KeycloakOpenIDManager:

    def __init__(
            self,
            server_url: str,
            client_id: str,
            client_secret: str,
            realm: str,
            callback_url: str,
            timeout: int = 10,
            verify: bool = True,
            custom_headers: dict = None,
            admin_client: bool = False,
    ):
        """

        :param server_url: Keycloak server url
        :param client_id: client id
        :param realm: _realm name
        :param client_secret: client secret key
        :param verify: True if want check connection SSL
        :param custom_headers: dict of custom header to pass to each HTML request
        :param admin_client: Admin client or User
        """
        self._server_url = server_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._callback_url = callback_url
        self._timeout = timeout
        self._realm = realm
        headers = dict()
        if custom_headers is not None:
            # merge custom headers to main headers
            headers.update(custom_headers)
        self._connection = ConnectionManager(base_url=server_url,
                                             headers=headers,
                                             timeout=60,
                                             verify=verify)

        self._authorization = Authorization()
        self.admin_client = admin_client

    @property
    def client_id(self):
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    @property
    def client_secret_key(self):
        return self._client_secret

    @client_secret_key.setter
    def client_secret_key(self, value):
        self._client_secret = value

    @property
    def realm_name(self):
        return self._realm

    @realm_name.setter
    def realm_name(self, value):
        self._realm = value

    @property
    def connection(self):
        return self._connection

    @connection.setter
    def connection(self, value):
        self._connection = value

    @property
    def authorization(self):
        return self._authorization

    @authorization.setter
    def authorization(self, value):
        self._authorization = value

    def _add_secret_key(self, payload):
        """
        Add secret key if exist.

        :param payload:
        :return:
        """
        if self._client_secret:
            payload.update({"_client_secret": self._client_secret})

        return payload

    def well_know(self):
        """ The most important endpoint to understand is the well-known configuration
            endpoint. It lists endpoints and other configuration options relevant to
            the OpenID Connect implementation in Keycloak.

            :return It lists endpoints and other configuration options relevant.
        """

        params_path = {"_realm-name": self._realm}
        data_raw = self.connection.raw_get(URL_WELL_KNOWN.format(**params_path))

        return raise_error_from_response(data_raw, KeycloakGetError)



    def certs(self):
        """
        The certificate endpoint returns the public keys enabled by the _realm, encoded as a
        JSON Web Key (JWK). Depending on the _realm settings there can be one or more keys enabled
        for verifying tokens.

        https://tools.ietf.org/html/rfc7517

        :return:
        """
        params_path = {"_realm-name": self.realm_name}
        data_raw = self.connection.raw_get(URL_CERTS.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def public_key_v1(self):
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
        params_path = {"realm-name": self._realm}
        data_raw = self.connection.raw_get(URL_REALM.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)['public_key']

    @functools.cached_property
    def realm_url(self):
        """The _realm's endpoint URL"""
        return f"{self._server_url}/realms/{self._realm}"

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
