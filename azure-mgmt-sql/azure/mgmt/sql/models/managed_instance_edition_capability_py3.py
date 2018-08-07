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


class ManagedInstanceEditionCapability(Model):
    """The managed server capability.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: The managed server version name.
    :vartype name: str
    :ivar supported_families: The supported families.
    :vartype supported_families:
     list[~azure.mgmt.sql.models.ManagedInstanceFamilyCapability]
    :ivar status: The status of the capability. Possible values include:
     'Visible', 'Available', 'Default', 'Disabled'
    :vartype status: str or ~azure.mgmt.sql.models.CapabilityStatus
    :param reason: The reason for the capability not being available.
    :type reason: str
    """

    _validation = {
        'name': {'readonly': True},
        'supported_families': {'readonly': True},
        'status': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'supported_families': {'key': 'supportedFamilies', 'type': '[ManagedInstanceFamilyCapability]'},
        'status': {'key': 'status', 'type': 'CapabilityStatus'},
        'reason': {'key': 'reason', 'type': 'str'},
    }

    def __init__(self, *, reason: str=None, **kwargs) -> None:
        super(ManagedInstanceEditionCapability, self).__init__(**kwargs)
        self.name = None
        self.supported_families = None
        self.status = None
        self.reason = reason
