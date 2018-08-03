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

from msrest.serialization import Model


class ServiceProviderParameter(Model):
    """Extra Parameters specific to each Service Provider.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Name of the Service Provider
    :vartype name: str
    :ivar type: Type of the Service Provider
    :vartype type: str
    :ivar display_name: Display Name of the Service Provider
    :vartype display_name: str
    :ivar description: Description of the Service Provider
    :vartype description: str
    :ivar help_url: Help Url for the  Service Provider
    :vartype help_url: str
    :ivar default: Default Name for the Service Provider
    :vartype default: str
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'display_name': {'readonly': True},
        'description': {'readonly': True},
        'help_url': {'readonly': True},
        'default': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'help_url': {'key': 'helpUrl', 'type': 'str'},
        'default': {'key': 'default', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(ServiceProviderParameter, self).__init__(**kwargs)
        self.name = None
        self.type = None
        self.display_name = None
        self.description = None
        self.help_url = None
        self.default = None
