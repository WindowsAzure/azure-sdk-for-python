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

from .proxy_resource_py3 import ProxyResource


class Configuration(ProxyResource):
    """Represents a Configuration.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param value: Value of the configuration.
    :type value: str
    :ivar description: Description of the configuration.
    :vartype description: str
    :ivar default_value: Default value of the configuration.
    :vartype default_value: str
    :ivar data_type: Data type of the configuration.
    :vartype data_type: str
    :ivar allowed_values: Allowed values of the configuration.
    :vartype allowed_values: str
    :param source: Source of the configuration.
    :type source: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'description': {'readonly': True},
        'default_value': {'readonly': True},
        'data_type': {'readonly': True},
        'allowed_values': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'value': {'key': 'properties.value', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'default_value': {'key': 'properties.defaultValue', 'type': 'str'},
        'data_type': {'key': 'properties.dataType', 'type': 'str'},
        'allowed_values': {'key': 'properties.allowedValues', 'type': 'str'},
        'source': {'key': 'properties.source', 'type': 'str'},
    }

    def __init__(self, *, value: str=None, source: str=None, **kwargs) -> None:
        super(Configuration, self).__init__(**kwargs)
        self.value = value
        self.description = None
        self.default_value = None
        self.data_type = None
        self.allowed_values = None
        self.source = source
