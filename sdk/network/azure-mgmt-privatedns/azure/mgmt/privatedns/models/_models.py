# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import msrest.serialization


class AaaaRecord(msrest.serialization.Model):
    """An AAAA record.

    :param ipv6_address: The IPv6 address of this AAAA record.
    :type ipv6_address: str
    """

    _attribute_map = {
        'ipv6_address': {'key': 'ipv6Address', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(AaaaRecord, self).__init__(**kwargs)
        self.ipv6_address = kwargs.get('ipv6_address', None)


class ARecord(msrest.serialization.Model):
    """An A record.

    :param ipv4_address: The IPv4 address of this A record.
    :type ipv4_address: str
    """

    _attribute_map = {
        'ipv4_address': {'key': 'ipv4Address', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ARecord, self).__init__(**kwargs)
        self.ipv4_address = kwargs.get('ipv4_address', None)


class CloudErrorBody(msrest.serialization.Model):
    """An error response from the service.

    :param code: An identifier for the error. Codes are invariant and are intended to be consumed
     programmatically.
    :type code: str
    :param message: A message describing the error, intended to be suitable for display in a user
     interface.
    :type message: str
    :param target: The target of the particular error. For example, the name of the property in
     error.
    :type target: str
    :param details: A list of additional details about the error.
    :type details: list[~azure.mgmt.privatedns.models.CloudErrorBody]
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[CloudErrorBody]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CloudErrorBody, self).__init__(**kwargs)
        self.code = kwargs.get('code', None)
        self.message = kwargs.get('message', None)
        self.target = kwargs.get('target', None)
        self.details = kwargs.get('details', None)


class CnameRecord(msrest.serialization.Model):
    """A CNAME record.

    :param cname: The canonical name for this CNAME record.
    :type cname: str
    """

    _attribute_map = {
        'cname': {'key': 'cname', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CnameRecord, self).__init__(**kwargs)
        self.cname = kwargs.get('cname', None)


class MxRecord(msrest.serialization.Model):
    """An MX record.

    :param preference: The preference value for this MX record.
    :type preference: int
    :param exchange: The domain name of the mail host for this MX record.
    :type exchange: str
    """

    _attribute_map = {
        'preference': {'key': 'preference', 'type': 'int'},
        'exchange': {'key': 'exchange', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(MxRecord, self).__init__(**kwargs)
        self.preference = kwargs.get('preference', None)
        self.exchange = kwargs.get('exchange', None)


class Resource(msrest.serialization.Model):
    """The core properties of ARM resources.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource Id for the resource. Example -
     '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/privateDnsZones/{privateDnsZoneName}'.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Example - 'Microsoft.Network/privateDnsZones'.
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class TrackedResource(Resource):
    """The resource model definition for a ARM tracked top level resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource Id for the resource. Example -
     '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/privateDnsZones/{privateDnsZoneName}'.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Example - 'Microsoft.Network/privateDnsZones'.
    :vartype type: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param location: The Azure Region where the resource lives.
    :type location: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TrackedResource, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
        self.location = kwargs.get('location', None)


class PrivateZone(TrackedResource):
    """Describes a Private DNS zone.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource Id for the resource. Example -
     '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/privateDnsZones/{privateDnsZoneName}'.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Example - 'Microsoft.Network/privateDnsZones'.
    :vartype type: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param location: The Azure Region where the resource lives.
    :type location: str
    :param etag: The ETag of the zone.
    :type etag: str
    :ivar max_number_of_record_sets: The maximum number of record sets that can be created in this
     Private DNS zone. This is a read-only property and any attempt to set this value will be
     ignored.
    :vartype max_number_of_record_sets: long
    :ivar number_of_record_sets: The current number of record sets in this Private DNS zone. This
     is a read-only property and any attempt to set this value will be ignored.
    :vartype number_of_record_sets: long
    :ivar max_number_of_virtual_network_links: The maximum number of virtual networks that can be
     linked to this Private DNS zone. This is a read-only property and any attempt to set this value
     will be ignored.
    :vartype max_number_of_virtual_network_links: long
    :ivar number_of_virtual_network_links: The current number of virtual networks that are linked
     to this Private DNS zone. This is a read-only property and any attempt to set this value will
     be ignored.
    :vartype number_of_virtual_network_links: long
    :ivar max_number_of_virtual_network_links_with_registration: The maximum number of virtual
     networks that can be linked to this Private DNS zone with registration enabled. This is a
     read-only property and any attempt to set this value will be ignored.
    :vartype max_number_of_virtual_network_links_with_registration: long
    :ivar number_of_virtual_network_links_with_registration: The current number of virtual networks
     that are linked to this Private DNS zone with registration enabled. This is a read-only
     property and any attempt to set this value will be ignored.
    :vartype number_of_virtual_network_links_with_registration: long
    :ivar provisioning_state: The provisioning state of the resource. This is a read-only property
     and any attempt to set this value will be ignored. Possible values include: "Creating",
     "Updating", "Deleting", "Succeeded", "Failed", "Canceled".
    :vartype provisioning_state: str or ~azure.mgmt.privatedns.models.ProvisioningState
    :ivar internal_id: Private zone internal Id.
    :vartype internal_id: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'max_number_of_record_sets': {'readonly': True},
        'number_of_record_sets': {'readonly': True},
        'max_number_of_virtual_network_links': {'readonly': True},
        'number_of_virtual_network_links': {'readonly': True},
        'max_number_of_virtual_network_links_with_registration': {'readonly': True},
        'number_of_virtual_network_links_with_registration': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'internal_id': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'max_number_of_record_sets': {'key': 'properties.maxNumberOfRecordSets', 'type': 'long'},
        'number_of_record_sets': {'key': 'properties.numberOfRecordSets', 'type': 'long'},
        'max_number_of_virtual_network_links': {'key': 'properties.maxNumberOfVirtualNetworkLinks', 'type': 'long'},
        'number_of_virtual_network_links': {'key': 'properties.numberOfVirtualNetworkLinks', 'type': 'long'},
        'max_number_of_virtual_network_links_with_registration': {'key': 'properties.maxNumberOfVirtualNetworkLinksWithRegistration', 'type': 'long'},
        'number_of_virtual_network_links_with_registration': {'key': 'properties.numberOfVirtualNetworkLinksWithRegistration', 'type': 'long'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'internal_id': {'key': 'properties.internalId', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateZone, self).__init__(**kwargs)
        self.etag = kwargs.get('etag', None)
        self.max_number_of_record_sets = None
        self.number_of_record_sets = None
        self.max_number_of_virtual_network_links = None
        self.number_of_virtual_network_links = None
        self.max_number_of_virtual_network_links_with_registration = None
        self.number_of_virtual_network_links_with_registration = None
        self.provisioning_state = None
        self.internal_id = None


class PrivateZoneListResult(msrest.serialization.Model):
    """The response to a Private DNS zone list operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param value: Information about the Private DNS zones.
    :type value: list[~azure.mgmt.privatedns.models.PrivateZone]
    :ivar next_link: The continuation token for the next page of results.
    :vartype next_link: str
    """

    _validation = {
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[PrivateZone]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PrivateZoneListResult, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = None


class ProxyResource(Resource):
    """The resource model definition for an ARM proxy resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource Id for the resource. Example -
     '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/privateDnsZones/{privateDnsZoneName}'.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Example - 'Microsoft.Network/privateDnsZones'.
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ProxyResource, self).__init__(**kwargs)


class PtrRecord(msrest.serialization.Model):
    """A PTR record.

    :param ptrdname: The PTR target domain name for this PTR record.
    :type ptrdname: str
    """

    _attribute_map = {
        'ptrdname': {'key': 'ptrdname', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(PtrRecord, self).__init__(**kwargs)
        self.ptrdname = kwargs.get('ptrdname', None)


class RecordSet(ProxyResource):
    """Describes a DNS record set (a collection of DNS records with the same name and type) in a Private DNS zone.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource Id for the resource. Example -
     '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/privateDnsZones/{privateDnsZoneName}'.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Example - 'Microsoft.Network/privateDnsZones'.
    :vartype type: str
    :param etag: The ETag of the record set.
    :type etag: str
    :param metadata: The metadata attached to the record set.
    :type metadata: dict[str, str]
    :param ttl: The TTL (time-to-live) of the records in the record set.
    :type ttl: long
    :ivar fqdn: Fully qualified domain name of the record set.
    :vartype fqdn: str
    :ivar is_auto_registered: Is the record set auto-registered in the Private DNS zone through a
     virtual network link?.
    :vartype is_auto_registered: bool
    :param a_records: The list of A records in the record set.
    :type a_records: list[~azure.mgmt.privatedns.models.ARecord]
    :param aaaa_records: The list of AAAA records in the record set.
    :type aaaa_records: list[~azure.mgmt.privatedns.models.AaaaRecord]
    :param cname_record: The CNAME record in the record set.
    :type cname_record: ~azure.mgmt.privatedns.models.CnameRecord
    :param mx_records: The list of MX records in the record set.
    :type mx_records: list[~azure.mgmt.privatedns.models.MxRecord]
    :param ptr_records: The list of PTR records in the record set.
    :type ptr_records: list[~azure.mgmt.privatedns.models.PtrRecord]
    :param soa_record: The SOA record in the record set.
    :type soa_record: ~azure.mgmt.privatedns.models.SoaRecord
    :param srv_records: The list of SRV records in the record set.
    :type srv_records: list[~azure.mgmt.privatedns.models.SrvRecord]
    :param txt_records: The list of TXT records in the record set.
    :type txt_records: list[~azure.mgmt.privatedns.models.TxtRecord]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'fqdn': {'readonly': True},
        'is_auto_registered': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'metadata': {'key': 'properties.metadata', 'type': '{str}'},
        'ttl': {'key': 'properties.ttl', 'type': 'long'},
        'fqdn': {'key': 'properties.fqdn', 'type': 'str'},
        'is_auto_registered': {'key': 'properties.isAutoRegistered', 'type': 'bool'},
        'a_records': {'key': 'properties.aRecords', 'type': '[ARecord]'},
        'aaaa_records': {'key': 'properties.aaaaRecords', 'type': '[AaaaRecord]'},
        'cname_record': {'key': 'properties.cnameRecord', 'type': 'CnameRecord'},
        'mx_records': {'key': 'properties.mxRecords', 'type': '[MxRecord]'},
        'ptr_records': {'key': 'properties.ptrRecords', 'type': '[PtrRecord]'},
        'soa_record': {'key': 'properties.soaRecord', 'type': 'SoaRecord'},
        'srv_records': {'key': 'properties.srvRecords', 'type': '[SrvRecord]'},
        'txt_records': {'key': 'properties.txtRecords', 'type': '[TxtRecord]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(RecordSet, self).__init__(**kwargs)
        self.etag = kwargs.get('etag', None)
        self.metadata = kwargs.get('metadata', None)
        self.ttl = kwargs.get('ttl', None)
        self.fqdn = None
        self.is_auto_registered = None
        self.a_records = kwargs.get('a_records', None)
        self.aaaa_records = kwargs.get('aaaa_records', None)
        self.cname_record = kwargs.get('cname_record', None)
        self.mx_records = kwargs.get('mx_records', None)
        self.ptr_records = kwargs.get('ptr_records', None)
        self.soa_record = kwargs.get('soa_record', None)
        self.srv_records = kwargs.get('srv_records', None)
        self.txt_records = kwargs.get('txt_records', None)


class RecordSetListResult(msrest.serialization.Model):
    """The response to a record set list operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param value: Information about the record sets in the response.
    :type value: list[~azure.mgmt.privatedns.models.RecordSet]
    :ivar next_link: The continuation token for the next page of results.
    :vartype next_link: str
    """

    _validation = {
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[RecordSet]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(RecordSetListResult, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = None


class SoaRecord(msrest.serialization.Model):
    """An SOA record.

    :param host: The domain name of the authoritative name server for this SOA record.
    :type host: str
    :param email: The email contact for this SOA record.
    :type email: str
    :param serial_number: The serial number for this SOA record.
    :type serial_number: long
    :param refresh_time: The refresh value for this SOA record.
    :type refresh_time: long
    :param retry_time: The retry time for this SOA record.
    :type retry_time: long
    :param expire_time: The expire time for this SOA record.
    :type expire_time: long
    :param minimum_ttl: The minimum value for this SOA record. By convention this is used to
     determine the negative caching duration.
    :type minimum_ttl: long
    """

    _attribute_map = {
        'host': {'key': 'host', 'type': 'str'},
        'email': {'key': 'email', 'type': 'str'},
        'serial_number': {'key': 'serialNumber', 'type': 'long'},
        'refresh_time': {'key': 'refreshTime', 'type': 'long'},
        'retry_time': {'key': 'retryTime', 'type': 'long'},
        'expire_time': {'key': 'expireTime', 'type': 'long'},
        'minimum_ttl': {'key': 'minimumTtl', 'type': 'long'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SoaRecord, self).__init__(**kwargs)
        self.host = kwargs.get('host', None)
        self.email = kwargs.get('email', None)
        self.serial_number = kwargs.get('serial_number', None)
        self.refresh_time = kwargs.get('refresh_time', None)
        self.retry_time = kwargs.get('retry_time', None)
        self.expire_time = kwargs.get('expire_time', None)
        self.minimum_ttl = kwargs.get('minimum_ttl', None)


class SrvRecord(msrest.serialization.Model):
    """An SRV record.

    :param priority: The priority value for this SRV record.
    :type priority: int
    :param weight: The weight value for this SRV record.
    :type weight: int
    :param port: The port value for this SRV record.
    :type port: int
    :param target: The target domain name for this SRV record.
    :type target: str
    """

    _attribute_map = {
        'priority': {'key': 'priority', 'type': 'int'},
        'weight': {'key': 'weight', 'type': 'int'},
        'port': {'key': 'port', 'type': 'int'},
        'target': {'key': 'target', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SrvRecord, self).__init__(**kwargs)
        self.priority = kwargs.get('priority', None)
        self.weight = kwargs.get('weight', None)
        self.port = kwargs.get('port', None)
        self.target = kwargs.get('target', None)


class SubResource(msrest.serialization.Model):
    """Reference to another subresource.

    :param id: Resource ID.
    :type id: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(SubResource, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)


class TxtRecord(msrest.serialization.Model):
    """A TXT record.

    :param value: The text value of this TXT record.
    :type value: list[str]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[str]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TxtRecord, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)


class VirtualNetworkLink(TrackedResource):
    """Describes a link to virtual network for a Private DNS zone.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource Id for the resource. Example -
     '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/privateDnsZones/{privateDnsZoneName}'.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. Example - 'Microsoft.Network/privateDnsZones'.
    :vartype type: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param location: The Azure Region where the resource lives.
    :type location: str
    :param etag: The ETag of the virtual network link.
    :type etag: str
    :param virtual_network: The reference of the virtual network.
    :type virtual_network: ~azure.mgmt.privatedns.models.SubResource
    :param registration_enabled: Is auto-registration of virtual machine records in the virtual
     network in the Private DNS zone enabled?.
    :type registration_enabled: bool
    :ivar virtual_network_link_state: The status of the virtual network link to the Private DNS
     zone. Possible values are 'InProgress' and 'Done'. This is a read-only property and any attempt
     to set this value will be ignored. Possible values include: "InProgress", "Completed".
    :vartype virtual_network_link_state: str or
     ~azure.mgmt.privatedns.models.VirtualNetworkLinkState
    :ivar provisioning_state: The provisioning state of the resource. This is a read-only property
     and any attempt to set this value will be ignored. Possible values include: "Creating",
     "Updating", "Deleting", "Succeeded", "Failed", "Canceled".
    :vartype provisioning_state: str or ~azure.mgmt.privatedns.models.ProvisioningState
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'virtual_network_link_state': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'virtual_network': {'key': 'properties.virtualNetwork', 'type': 'SubResource'},
        'registration_enabled': {'key': 'properties.registrationEnabled', 'type': 'bool'},
        'virtual_network_link_state': {'key': 'properties.virtualNetworkLinkState', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(VirtualNetworkLink, self).__init__(**kwargs)
        self.etag = kwargs.get('etag', None)
        self.virtual_network = kwargs.get('virtual_network', None)
        self.registration_enabled = kwargs.get('registration_enabled', None)
        self.virtual_network_link_state = None
        self.provisioning_state = None


class VirtualNetworkLinkListResult(msrest.serialization.Model):
    """The response to a list virtual network link to Private DNS zone operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param value: Information about the virtual network links to the Private DNS zones.
    :type value: list[~azure.mgmt.privatedns.models.VirtualNetworkLink]
    :ivar next_link: The continuation token for the next page of results.
    :vartype next_link: str
    """

    _validation = {
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[VirtualNetworkLink]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(VirtualNetworkLinkListResult, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = None
