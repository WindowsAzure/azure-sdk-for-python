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

from .resource_py3 import Resource


class DdosCustomPolicy(Resource):
    """A DDoS custom policy in a resource group.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :ivar resource_guid: The resource GUID property of the DDoS custom policy
     resource. It uniquely identifies the resource, even if the user changes
     its name or migrate the resource across subscriptions or resource groups.
    :vartype resource_guid: str
    :ivar provisioning_state: The provisioning state of the DDoS custom policy
     resource. Possible values are: 'Succeeded', 'Updating', 'Deleting', and
     'Failed'.
    :vartype provisioning_state: str
    :ivar public_ip_addresses: The list of public IPs associated with the DDoS
     custom policy resource. This list is read-only.
    :vartype public_ip_addresses:
     list[~azure.mgmt.network.v2018_12_01.models.SubResource]
    :param protocol_custom_settings: The protocol-specific DDoS policy
     customization parameters.
    :type protocol_custom_settings:
     list[~azure.mgmt.network.v2018_12_01.models.ProtocolCustomSettingsFormat]
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'resource_guid': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'public_ip_addresses': {'readonly': True},
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'resource_guid': {'key': 'properties.resourceGuid', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'public_ip_addresses': {'key': 'properties.publicIPAddresses', 'type': '[SubResource]'},
        'protocol_custom_settings': {'key': 'properties.protocolCustomSettings', 'type': '[ProtocolCustomSettingsFormat]'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, location: str=None, tags=None, protocol_custom_settings=None, **kwargs) -> None:
        super(DdosCustomPolicy, self).__init__(id=id, location=location, tags=tags, **kwargs)
        self.resource_guid = None
        self.provisioning_state = None
        self.public_ip_addresses = None
        self.protocol_custom_settings = protocol_custom_settings
        self.etag = None
