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
__init__.py  
  
created by dromakin as 09.10.2022  
Project fastapi-keycloak  
"""

__author__ = 'dromakin'
__maintainer__ = 'dromakin'
__credits__ = ['dromakin', ]
__copyright__ = "Dromakin, Inc, 2022"
__status__ = 'Development'
__version__ = 20221009


import ast
import json

from fastapi_keycloak_manager.core.auth.permission import Permission
from fastapi_keycloak_manager.core.auth.policy import Policy
from fastapi_keycloak_manager.core.auth.role import Role


class Authorization:
    """
    Keycloak Authorization (policies, roles, scopes and resources).

    https://keycloak.gitbooks.io/documentation/authorization_services/index.html

    """

    def __init__(self):
        self._policies = {}

    @property
    def policies(self):
        return self._policies

    @policies.setter
    def policies(self, value):
        self._policies = value

    def load_config(self, data):
        """
        Load policies, roles and permissions (scope/resources).

        :param data: keycloak authorization data (dict)
        :return:
        """
        for pol in data['policies']:
            if pol['type'] == 'role':
                policy = Policy(name=pol['name'],
                                type=pol['type'],
                                logic=pol['logic'],
                                decision_strategy=pol['decisionStrategy'])

                config_roles = json.loads(pol['config']['roles'])
                for role in config_roles:
                    policy.add_role(Role(name=role['id'],
                                         required=role['required']))

                self.policies[policy.name] = policy

            if pol['type'] == 'scope':
                permission = Permission(name=pol['name'],
                                        type=pol['type'],
                                        logic=pol['logic'],
                                        decision_strategy=pol['decisionStrategy'])

                permission.scopes = ast.literal_eval(pol['config']['scopes'])

                for policy_name in ast.literal_eval(pol['config']['applyPolicies']):
                    self.policies[policy_name].add_permission(permission)

            if pol['type'] == 'resource':
                permission = Permission(name=pol['name'],
                                        type=pol['type'],
                                        logic=pol['logic'],
                                        decision_strategy=pol['decisionStrategy'])

                permission.resources = ast.literal_eval(pol['config'].get('resources', "[]"))

                for policy_name in ast.literal_eval(pol['config']['applyPolicies']):
                    if self.policies.get(policy_name) is not None:
                        self.policies[policy_name].add_permission(permission)

    def load_authorization_config(self, path):
        """
        Load Keycloak settings (authorization)

        :param path: settings file (json)
        :return:
        """
        authorization_file = open(path, 'r')
        authorization_json = json.loads(authorization_file.read())
        self.load_config(authorization_json)
        authorization_file.close()
