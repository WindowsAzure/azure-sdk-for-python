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


class ClientDiscoveryValueForSingleApi(Model):
    """Available operation details.

    :param name: Name of the Operation.
    :type name: str
    :param display: Contains the localized display information for this
     particular operation
    :type display: ~azure.mgmt.recoveryservices.models.ClientDiscoveryDisplay
    :param origin: The intended executor of the operation;governs the display
     of the operation in the RBAC UX and the audit logs UX
    :type origin: str
    :param properties: ShoeBox properties for the given operation.
    :type properties:
     ~azure.mgmt.recoveryservices.models.ClientDiscoveryForProperties
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'ClientDiscoveryDisplay'},
        'origin': {'key': 'origin', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'ClientDiscoveryForProperties'},
    }

    def __init__(self, name=None, display=None, origin=None, properties=None):
        super(ClientDiscoveryValueForSingleApi, self).__init__()
        self.name = name
        self.display = display
        self.origin = origin
        self.properties = properties
