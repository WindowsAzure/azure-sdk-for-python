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


class ProviderOperationsMetadata(Model):
    """Provider Operations metadata.

    :param id: The provider id.
    :type id: str
    :param name: The provider name.
    :type name: str
    :param type: The provider type.
    :type type: str
    :param display_name: The provider display name.
    :type display_name: str
    :param resource_types: The provider resource types
    :type resource_types: list[~azure.mgmt.authorization.models.ResourceType]
    :param operations: The provider operations.
    :type operations: list[~azure.mgmt.authorization.models.ProviderOperation]
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'resource_types': {'key': 'resourceTypes', 'type': '[ResourceType]'},
        'operations': {'key': 'operations', 'type': '[ProviderOperation]'},
    }

    def __init__(self, **kwargs):
        super(ProviderOperationsMetadata, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.name = kwargs.get('name', None)
        self.type = kwargs.get('type', None)
        self.display_name = kwargs.get('display_name', None)
        self.resource_types = kwargs.get('resource_types', None)
        self.operations = kwargs.get('operations', None)
