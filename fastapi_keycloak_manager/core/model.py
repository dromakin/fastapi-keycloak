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

__author__ = 'dromakin'
__maintainer__ = 'dromakin'
__credits__ = ['dromakin', ]
__copyright__ = "Dromakin, Inc, 2022"
__status__ = 'Development'
__version__ = 20221009

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, SecretStr, Field

from .exceptions import KeycloakError


class HTTPMethod(Enum):
    """Represents the basic HTTP verbs

    Values:
        - GET: get
        - POST: post
        - DELETE: delete
        - PUT: put
    """

    GET = "get"
    POST = "post"
    DELETE = "delete"
    PUT = "put"


class KeycloakUser(BaseModel):
    """Represents a user object of Keycloak.

    Attributes:
        id (str):
        createdTimestamp (int):
        _username (str):
        enabled (bool):
        totp (bool):
        emailVerified (bool):
        firstName (Optional[str]):
        lastName (Optional[str]):
        email (Optional[str]):
        disableableCredentialTypes (List[str]):
        requiredActions (List[str]):
        realmRoles (List[str]):
        notBefore (int):
        access (dict):
        attributes (Optional[dict]):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    id: str
    createdTimestamp: int
    username: str
    enabled: bool
    totp: bool
    emailVerified: bool
    firstName: Optional[str]
    lastName: Optional[str]
    email: Optional[str]
    disableableCredentialTypes: List[str]
    requiredActions: List[str]
    realmRoles: Optional[List[str]]
    notBefore: int
    access: dict
    attributes: Optional[dict]


class UsernamePassword(BaseModel):
    """Represents a request body that contains _username and _password

    Attributes:
        _username (str): Username
        _password (str): Password, masked by swagger
    """

    username: str
    password: SecretStr


class OIDCUser(BaseModel):
    """Represents a user object of Keycloak, parsed from access _site_token

    Attributes:
        sub (str):
        iat (int):
        exp (int):
        scope (str):
        email_verified (bool):
        name (Optional[str]):
        given_name (Optional[str]):
        family_name (Optional[str]):
        email (Optional[str]):
        preferred_username (Optional[str]):
        realm_access (dict):
        resource_access (dict):
        extra_fields (dict):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    sub: str
    iat: int
    exp: int
    scope: Optional[str]
    email_verified: bool
    name: Optional[str]
    given_name: Optional[str]
    family_name: Optional[str]
    email: Optional[str]
    preferred_username: Optional[str]
    realm_access: Optional[dict]
    resource_access: Optional[dict]
    extra_fields: dict = Field(default_factory=dict)

    @property
    def roles(self) -> List[str]:
        """Returns the roles of the user

        Returns:
            List[str]: If the _realm access dict contains roles
        """
        if not self.realm_access:
            raise KeycloakError(
                status_code=404,
                reason="The 'realm_access' section of the provided access _site_token is missing",
            )
        try:
            return self.realm_access["roles"]
        except KeyError as e:
            raise KeycloakError(
                status_code=404,
                reason="The 'realm_access' section of the provided access _site_token did not contain any 'roles'",
            ) from e

    def __str__(self) -> str:
        """String representation of an OIDCUser"""
        return self.preferred_username


class KeycloakIdentityProvider(BaseModel):
    """Keycloak representation of an identity provider

    Attributes:
        alias (str):
        internalId (str):
        providerId (str):
        enabled (bool):
        updateProfileFirstLoginMode (str):
        trustEmail (bool):
        storeToken (bool):
        addReadTokenRoleOnCreate (bool):
        authenticateByDefault (bool):
        linkOnly (bool):
        firstBrokerLoginFlowAlias (str):
        config (dict):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    alias: str
    internalId: str
    providerId: str
    enabled: bool
    updateProfileFirstLoginMode: str
    trustEmail: bool
    storeToken: bool
    addReadTokenRoleOnCreate: bool
    authenticateByDefault: bool
    linkOnly: bool
    firstBrokerLoginFlowAlias: str
    config: dict


class KeycloakRole(BaseModel):
    """Keycloak representation of a role

    Attributes:
        id (str):
        name (str):
        composite (bool):
        clientRole (bool):
        containerId (str):

    Notes: Check the Keycloak documentation at https://www.keycloak.org/docs-api/15.0/rest-api/index.html for
    details. This is a mere proxy object.
    """

    id: str
    name: str
    composite: bool
    clientRole: bool
    containerId: str


class KeycloakToken(BaseModel):
    """Keycloak representation of a _site_token object

    Attributes:
        access_token (str): An access _site_token
    """

    access_token: str

    def __str__(self):
        """String representation of KeycloakToken"""
        return f"Bearer {self.access_token}"


class KeycloakGroup(BaseModel):
    """Keycloak representation of a group

    Attributes:
        id (str):
        name (str):
        path (Optional[str]):
        realmRoles (Optional[str]):
    """

    id: str
    name: str
    path: Optional[str]
    realmRoles: Optional[List[str]]
    subGroups: Optional[List["KeycloakGroup"]]


KeycloakGroup.update_forward_refs()
