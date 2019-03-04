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


class PublicIPPrefix(Resource):
    """Public IP prefix resource.

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
    :param sku: The public IP prefix SKU.
    :type sku: ~azure.mgmt.network.v2018_12_01.models.PublicIPPrefixSku
    :param public_ip_address_version: The public IP address version. Possible
     values are: 'IPv4' and 'IPv6'. Possible values include: 'IPv4', 'IPv6'
    :type public_ip_address_version: str or
     ~azure.mgmt.network.v2018_12_01.models.IPVersion
    :param ip_tags: The list of tags associated with the public IP prefix.
    :type ip_tags: list[~azure.mgmt.network.v2018_12_01.models.IpTag]
    :param prefix_length: The Length of the Public IP Prefix.
    :type prefix_length: int
    :param ip_prefix: The allocated Prefix
    :type ip_prefix: str
    :param public_ip_addresses: The list of all referenced PublicIPAddresses
    :type public_ip_addresses:
     list[~azure.mgmt.network.v2018_12_01.models.ReferencedPublicIpAddress]
    :param resource_guid: The resource GUID property of the public IP prefix
     resource.
    :type resource_guid: str
    :param provisioning_state: The provisioning state of the Public IP prefix
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
    :type provisioning_state: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    :param zones: A list of availability zones denoting the IP allocated for
     the resource needs to come from.
    :type zones: list[str]
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'PublicIPPrefixSku'},
        'public_ip_address_version': {'key': 'properties.publicIPAddressVersion', 'type': 'str'},
        'ip_tags': {'key': 'properties.ipTags', 'type': '[IpTag]'},
        'prefix_length': {'key': 'properties.prefixLength', 'type': 'int'},
        'ip_prefix': {'key': 'properties.ipPrefix', 'type': 'str'},
        'public_ip_addresses': {'key': 'properties.publicIPAddresses', 'type': '[ReferencedPublicIpAddress]'},
        'resource_guid': {'key': 'properties.resourceGuid', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'zones': {'key': 'zones', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(PublicIPPrefix, self).__init__(**kwargs)
        self.sku = kwargs.get('sku', None)
        self.public_ip_address_version = kwargs.get('public_ip_address_version', None)
        self.ip_tags = kwargs.get('ip_tags', None)
        self.prefix_length = kwargs.get('prefix_length', None)
        self.ip_prefix = kwargs.get('ip_prefix', None)
        self.public_ip_addresses = kwargs.get('public_ip_addresses', None)
        self.resource_guid = kwargs.get('resource_guid', None)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.etag = kwargs.get('etag', None)
        self.zones = kwargs.get('zones', None)
