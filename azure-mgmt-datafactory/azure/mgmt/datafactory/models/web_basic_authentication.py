# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .web_linked_service_type_properties import WebLinkedServiceTypeProperties


class WebBasicAuthentication(WebLinkedServiceTypeProperties):
    """A WebLinkedService that uses basic authentication to communicate with an
    HTTP endpoint.

    :param url: The URL of the web service endpoint, e.g.
     http://www.microsoft.com . Type: string (or Expression with resultType
     string).
    :type url: object
    :param authentication_type: Constant filled by server.
    :type authentication_type: str
    :param username: User name for Basic authentication. Type: string (or
     Expression with resultType string).
    :type username: object
    :param password: The password for Basic authentication.
    :type password: ~azure.mgmt.datafactory.models.SecretBase
    """

    _validation = {
        'url': {'required': True},
        'authentication_type': {'required': True},
        'username': {'required': True},
        'password': {'required': True},
    }

    _attribute_map = {
        'url': {'key': 'url', 'type': 'object'},
        'authentication_type': {'key': 'authenticationType', 'type': 'str'},
        'username': {'key': 'username', 'type': 'object'},
        'password': {'key': 'password', 'type': 'SecretBase'},
    }

    def __init__(self, url, username, password):
        super(WebBasicAuthentication, self).__init__(url=url)
        self.username = username
        self.password = password
        self.authentication_type = 'Basic'
