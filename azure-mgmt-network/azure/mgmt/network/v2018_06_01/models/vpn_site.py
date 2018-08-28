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


class VpnSite(Resource):
    """VpnSite Resource.

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
    :param virtual_wan: The VirtualWAN to which the vpnSite belongs
    :type virtual_wan: ~azure.mgmt.network.v2018_06_01.models.SubResource
    :param device_properties: The device properties
    :type device_properties:
     ~azure.mgmt.network.v2018_06_01.models.DeviceProperties
    :param ip_address: The ip-address for the vpn-site.
    :type ip_address: str
    :param site_key: The key for vpn-site that can be used for connections.
    :type site_key: str
    :param address_space: The AddressSpace that contains an array of IP
     address ranges.
    :type address_space: ~azure.mgmt.network.v2018_06_01.models.AddressSpace
    :param bgp_properties: The set of bgp properties.
    :type bgp_properties: ~azure.mgmt.network.v2018_06_01.models.BgpSettings
    :param provisioning_state: The provisioning state of the resource.
     Possible values include: 'Succeeded', 'Updating', 'Deleting', 'Failed'
    :type provisioning_state: str or
     ~azure.mgmt.network.v2018_06_01.models.ProvisioningState
    :ivar etag: Gets a unique read-only string that changes whenever the
     resource is updated.
    :vartype etag: str
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'virtual_wan': {'key': 'properties.virtualWAN', 'type': 'SubResource'},
        'device_properties': {'key': 'properties.deviceProperties', 'type': 'DeviceProperties'},
        'ip_address': {'key': 'properties.ipAddress', 'type': 'str'},
        'site_key': {'key': 'properties.siteKey', 'type': 'str'},
        'address_space': {'key': 'properties.addressSpace', 'type': 'AddressSpace'},
        'bgp_properties': {'key': 'properties.bgpProperties', 'type': 'BgpSettings'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(VpnSite, self).__init__(**kwargs)
        self.virtual_wan = kwargs.get('virtual_wan', None)
        self.device_properties = kwargs.get('device_properties', None)
        self.ip_address = kwargs.get('ip_address', None)
        self.site_key = kwargs.get('site_key', None)
        self.address_space = kwargs.get('address_space', None)
        self.bgp_properties = kwargs.get('bgp_properties', None)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.etag = None
