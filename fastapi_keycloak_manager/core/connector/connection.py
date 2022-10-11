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
connection.py  
  
created by dromakin as 08.10.2022  
Project fastapi-keycloak  
"""

__author__ = 'dromakin'
__maintainer__ = 'dromakin'
__credits__ = ['dromakin', ]
__copyright__ = "Dromakin, Inc, 2022"
__status__ = 'Development'
__version__ = 20221008

import functools
import json
from json import JSONDecodeError
from typing import List, Type
from urllib.parse import urljoin

import requests
from pydantic import BaseModel
from requests import Response
from requests.adapters import HTTPAdapter

from fastapi_keycloak.exceptions import (
    KeycloakError,
)

from ..model import (
    HTTPMethod,
)

from fastapi_keycloak_manager.core.exceptions import KeycloakConnectionError


def result_or_error(
        response_model: Type[BaseModel] = None, is_list: bool = False
) -> List[BaseModel] or BaseModel or KeycloakError:
    """Decorator used to ease the handling of responses from Keycloak.

    Args:
        response_model (Type[BaseModel]): Object that should be returned based on the payload
        is_list (bool): True if the return value should be a list of the response model provided

    Returns:
        BaseModel or List[BaseModel]: Based on the given signature and response circumstances

    Raises:
        KeycloakError: If the resulting response is not a successful HTTP-Code (>299)

    Notes:
        - Keycloak sometimes returns empty payloads but describes the error in its content (byte encoded)
          which is why this function checks for JSONDecode exceptions.
        - Keycloak often does not expose the real error for securlty measures. You will most likely encounter:
          {'error': 'unknown_error'} as a result. If so, please check the logs of your Keycloak instance to get error
          details, the RestAPI doesn't provide any.
    """

    def inner(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            def create_list(json_data: List[dict]):
                return [response_model.parse_obj(entry) for entry in json_data]

            def create_object(json_data: dict):
                return response_model.parse_obj(json_data)

            result: Response = f(*args, **kwargs)  # The actual call

            if (
                    type(result) != Response
            ):  # If the object given is not a response object, directly return it.
                return result

            if result.status_code in range(100, 299):  # Successful
                if response_model is None:  # No model given

                    try:
                        return result.json()
                    except JSONDecodeError:
                        return result.content.decode("utf-8")

                else:  # Response model given
                    if is_list:
                        return create_list(result.json())
                    else:
                        return create_object(result.json())

            else:  # Not Successful, forward status code and error
                try:
                    raise KeycloakError(
                        status_code=result.status_code, reason=result.json()
                    )
                except JSONDecodeError:
                    raise KeycloakError(
                        status_code=result.status_code,
                        reason=result.content.decode("utf-8"),
                    )

        return wrapper

    return inner


class ConnectionManager(object):
    """Represents a simple server connection.

    Args:
        base_url (str): The server URL.
        headers (dict): The header parameters of the requests to the server.
        timeout (int): Timeout to use for requests to the server.
        verify (bool): Verify server SSL.
    """

    def __init__(self, base_url, headers={}, timeout=60, verify=True):
        self._base_url = base_url
        self._headers = headers
        self._timeout = timeout
        self._verify = verify
        self._s = requests.Session()
        self._s.auth = lambda x: x  # don't let requests add core headers

        for protocol in ('https://', 'http://'):
            adapter = HTTPAdapter(max_retries=1)
            # adds POST to retry whitelist
            method_whitelist = set(adapter.max_retries.method_whitelist)
            method_whitelist.add('POST')
            adapter.max_retries.method_whitelist = frozenset(method_whitelist)

            self._s.mount(protocol, adapter)

    @property
    def base_url(self):
        """ Return base url in use for requests to the server. """
        return self._base_url

    @base_url.setter
    def base_url(self, value):
        """ """
        self._base_url = value

    @property
    def timeout(self):
        """ Return _timeout in use for request to the server. """
        return self._timeout

    @timeout.setter
    def timeout(self, value):
        """ """
        self._timeout = value

    @property
    def verify(self):
        """ Return _verify in use for request to the server. """
        return self._verify

    @verify.setter
    def verify(self, value):
        """ """
        self._verify = value

    @property
    def headers(self):
        """ Return header request to the server. """
        return self._headers

    @headers.setter
    def headers(self, value):
        """ """
        self._headers = value

    def param_headers(self, key):
        """ Return a specific header parameter.
        :arg
            key (str): Header parameters key.
        :return:
            If the header parameters exist, return its value.
        """
        return self._headers.get(key)

    def clean_headers(self):
        """ Clear header parameters. """
        self._headers = {}

    def exist_param_headers(self, key):
        """ Check if the parameter exists in the header.
        :arg
            key (str): Header parameters key.
        :return:
            If the header parameters exist, return True.
        """
        return self.param_headers(key) is not None

    def add_param_headers(self, key, value):
        """ Add a single parameter inside the header.
        :arg
            key (str): Header parameters key.
            value (str): Value to be added.
        """
        self._headers[key] = value

    def del_param_headers(self, key):
        """ Remove a specific parameter.
        :arg
            key (str): Key of the header parameters.
        """
        self._headers.pop(key, None)

    def raw_get(self, path, **kwargs):
        """ Submit get request to the path.
        :arg
            path (str): Path for request.
        :return
            Response the request.
        :exception
            HttpError: Can't connect to server.
        """

        try:
            return self._s.get(urljoin(self._base_url, path),
                               params=kwargs,
                               headers=self._headers,
                               timeout=self._timeout,
                               verify=self._verify)
        except Exception as e:
            raise KeycloakConnectionError(
                "Can't connect to server (%s)" % e)

    def raw_post(self, path, data, **kwargs):
        """ Submit post request to the path.
        :arg
            path (str): Path for request.
            data (dict): Payload for request.
        :return
            Response the request.
        :exception
            HttpError: Can't connect to server.
        """
        try:
            return self._s.post(urljoin(self._base_url, path),
                                params=kwargs,
                                data=data,
                                headers=self._headers,
                                timeout=self._timeout,
                                verify=self._verify)
        except Exception as e:
            raise KeycloakConnectionError(
                "Can't connect to server (%s)" % e)

    def raw_put(self, path, data, **kwargs):
        """ Submit put request to the path.
        :arg
            path (str): Path for request.
            data (dict): Payload for request.
        :return
            Response the request.
        :exception
            HttpError: Can't connect to server.
        """
        try:
            return self._s.put(urljoin(self._base_url, path),
                               params=kwargs,
                               data=data,
                               headers=self._headers,
                               timeout=self._timeout,
                               verify=self._verify)
        except Exception as e:
            raise KeycloakConnectionError(
                "Can't connect to server (%s)" % e)

    def raw_delete(self, path, data={}, **kwargs):
        """ Submit delete request to the path.

        :arg
            path (str): Path for request.
            data (dict): Payload for request.
        :return
            Response the request.
        :exception
            HttpError: Can't connect to server.
        """
        try:
            return self._s.delete(urljoin(self._base_url, path),
                                  params=kwargs,
                                  data=data,
                                  headers=self._headers,
                                  timeout=self._timeout,
                                  verify=self._verify)
        except Exception as e:
            raise KeycloakConnectionError(
                "Can't connect to server (%s)" % e)

    def make_request(
            self,
            url: str,
            method: HTTPMethod,
            data: dict = None,
            headers: dict = None,
    ) -> Response:
        """Private method that is the basis for any requests requiring admin access to the api. Will append the
        necessary `Authorization` header

        Args:
            url (str): The URL to be called
            method (HTTPMethod): The HTTP verb to be used
            data (dict): The payload of the request
            headers (dict): The content type of the request

        Returns:
            Response: Response of Keycloak
        """
        # headers = {
        #     "Content-Type": "application/json",
        #     "Authorization": f"Bearer {self.admin_token}",
        # }
        return requests.request(
            method=method.name, url=url, data=json.dumps(data), headers=headers, timeout=self._timeout,
        )
