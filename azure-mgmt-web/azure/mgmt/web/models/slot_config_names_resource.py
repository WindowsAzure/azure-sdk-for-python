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

from .resource import Resource


class SlotConfigNamesResource(Resource):
    """Slot Config names azure resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :param location: Resource Location.
    :type location: str
    :ivar type: Resource type.
    :vartype type: str
    :param tags: Resource tags.
    :type tags: dict
    :param connection_string_names: List of connection string names.
    :type connection_string_names: list of str
    :param app_setting_names: List of application settings names.
    :type app_setting_names: list of str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'location': {'required': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'connection_string_names': {'key': 'properties.connectionStringNames', 'type': '[str]'},
        'app_setting_names': {'key': 'properties.appSettingNames', 'type': '[str]'},
    }

    def __init__(self, location, kind=None, tags=None, connection_string_names=None, app_setting_names=None):
        super(SlotConfigNamesResource, self).__init__(kind=kind, location=location, tags=tags)
        self.connection_string_names = connection_string_names
        self.app_setting_names = app_setting_names
