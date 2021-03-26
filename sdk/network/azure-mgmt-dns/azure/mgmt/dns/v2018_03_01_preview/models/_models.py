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


class CaaRecord(msrest.serialization.Model):
    """A CAA record.

    :param flags: The flags for this CAA record as an integer between 0 and 255.
    :type flags: int
    :param tag: The tag for this CAA record.
    :type tag: str
    :param value: The value for this CAA record.
    :type value: str
    """

    _attribute_map = {
        'flags': {'key': 'flags', 'type': 'int'},
        'tag': {'key': 'tag', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(CaaRecord, self).__init__(**kwargs)
        self.flags = kwargs.get('flags', None)
        self.tag = kwargs.get('tag', None)
        self.value = kwargs.get('value', None)


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
    :type details: list[~azure.mgmt.dns.v2018_03_01_preview.models.CloudErrorBody]
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


class NsRecord(msrest.serialization.Model):
    """An NS record.

    :param nsdname: The name server name for this NS record.
    :type nsdname: str
    """

    _attribute_map = {
        'nsdname': {'key': 'nsdname', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(NsRecord, self).__init__(**kwargs)
        self.nsdname = kwargs.get('nsdname', None)


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


class RecordSet(msrest.serialization.Model):
    """Describes a DNS record set (a collection of DNS records with the same name and type).

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The ID of the record set.
    :vartype id: str
    :ivar name: The name of the record set.
    :vartype name: str
    :ivar type: The type of the record set.
    :vartype type: str
    :param etag: The etag of the record set.
    :type etag: str
    :param metadata: The metadata attached to the record set.
    :type metadata: dict[str, str]
    :param ttl: The TTL (time-to-live) of the records in the record set.
    :type ttl: long
    :ivar fqdn: Fully qualified domain name of the record set.
    :vartype fqdn: str
    :param a_records: The list of A records in the record set.
    :type a_records: list[~azure.mgmt.dns.v2018_03_01_preview.models.ARecord]
    :param aaaa_records: The list of AAAA records in the record set.
    :type aaaa_records: list[~azure.mgmt.dns.v2018_03_01_preview.models.AaaaRecord]
    :param mx_records: The list of MX records in the record set.
    :type mx_records: list[~azure.mgmt.dns.v2018_03_01_preview.models.MxRecord]
    :param ns_records: The list of NS records in the record set.
    :type ns_records: list[~azure.mgmt.dns.v2018_03_01_preview.models.NsRecord]
    :param ptr_records: The list of PTR records in the record set.
    :type ptr_records: list[~azure.mgmt.dns.v2018_03_01_preview.models.PtrRecord]
    :param srv_records: The list of SRV records in the record set.
    :type srv_records: list[~azure.mgmt.dns.v2018_03_01_preview.models.SrvRecord]
    :param txt_records: The list of TXT records in the record set.
    :type txt_records: list[~azure.mgmt.dns.v2018_03_01_preview.models.TxtRecord]
    :param cname_record: The CNAME record in the  record set.
    :type cname_record: ~azure.mgmt.dns.v2018_03_01_preview.models.CnameRecord
    :param soa_record: The SOA record in the record set.
    :type soa_record: ~azure.mgmt.dns.v2018_03_01_preview.models.SoaRecord
    :param caa_records: The list of CAA records in the record set.
    :type caa_records: list[~azure.mgmt.dns.v2018_03_01_preview.models.CaaRecord]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'fqdn': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'metadata': {'key': 'properties.metadata', 'type': '{str}'},
        'ttl': {'key': 'properties.TTL', 'type': 'long'},
        'fqdn': {'key': 'properties.fqdn', 'type': 'str'},
        'a_records': {'key': 'properties.ARecords', 'type': '[ARecord]'},
        'aaaa_records': {'key': 'properties.AAAARecords', 'type': '[AaaaRecord]'},
        'mx_records': {'key': 'properties.MXRecords', 'type': '[MxRecord]'},
        'ns_records': {'key': 'properties.NSRecords', 'type': '[NsRecord]'},
        'ptr_records': {'key': 'properties.PTRRecords', 'type': '[PtrRecord]'},
        'srv_records': {'key': 'properties.SRVRecords', 'type': '[SrvRecord]'},
        'txt_records': {'key': 'properties.TXTRecords', 'type': '[TxtRecord]'},
        'cname_record': {'key': 'properties.CNAMERecord', 'type': 'CnameRecord'},
        'soa_record': {'key': 'properties.SOARecord', 'type': 'SoaRecord'},
        'caa_records': {'key': 'properties.caaRecords', 'type': '[CaaRecord]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(RecordSet, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.etag = kwargs.get('etag', None)
        self.metadata = kwargs.get('metadata', None)
        self.ttl = kwargs.get('ttl', None)
        self.fqdn = None
        self.a_records = kwargs.get('a_records', None)
        self.aaaa_records = kwargs.get('aaaa_records', None)
        self.mx_records = kwargs.get('mx_records', None)
        self.ns_records = kwargs.get('ns_records', None)
        self.ptr_records = kwargs.get('ptr_records', None)
        self.srv_records = kwargs.get('srv_records', None)
        self.txt_records = kwargs.get('txt_records', None)
        self.cname_record = kwargs.get('cname_record', None)
        self.soa_record = kwargs.get('soa_record', None)
        self.caa_records = kwargs.get('caa_records', None)


class RecordSetListResult(msrest.serialization.Model):
    """The response to a record set List operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param value: Information about the record sets in the response.
    :type value: list[~azure.mgmt.dns.v2018_03_01_preview.models.RecordSet]
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


class RecordSetUpdateParameters(msrest.serialization.Model):
    """Parameters supplied to update a record set.

    :param record_set: Specifies information about the record set being updated.
    :type record_set: ~azure.mgmt.dns.v2018_03_01_preview.models.RecordSet
    """

    _attribute_map = {
        'record_set': {'key': 'RecordSet', 'type': 'RecordSet'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(RecordSetUpdateParameters, self).__init__(**kwargs)
        self.record_set = kwargs.get('record_set', None)


class Resource(msrest.serialization.Model):
    """Common fields that are returned in the response for all Azure Resource Manager resources.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. E.g. "Microsoft.Compute/virtualMachines" or
     "Microsoft.Storage/storageAccounts".
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
        'minimum_ttl': {'key': 'minimumTTL', 'type': 'long'},
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
    """A reference to a another resource.

    :param id: Resource Id.
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


class TrackedResource(Resource):
    """The resource model definition for an Azure Resource Manager tracked top level resource which has 'tags' and a 'location'.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. E.g. "Microsoft.Compute/virtualMachines" or
     "Microsoft.Storage/storageAccounts".
    :vartype type: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param location: Required. The geo-location where the resource lives.
    :type location: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
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
        self.location = kwargs['location']


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


class Zone(TrackedResource):
    """Describes a DNS zone.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. E.g. "Microsoft.Compute/virtualMachines" or
     "Microsoft.Storage/storageAccounts".
    :vartype type: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param location: Required. The geo-location where the resource lives.
    :type location: str
    :param etag: The etag of the zone.
    :type etag: str
    :ivar max_number_of_record_sets: The maximum number of record sets that can be created in this
     DNS zone.  This is a read-only property and any attempt to set this value will be ignored.
    :vartype max_number_of_record_sets: long
    :ivar max_number_of_records_per_record_set: The maximum number of records per record set that
     can be created in this DNS zone.  This is a read-only property and any attempt to set this
     value will be ignored.
    :vartype max_number_of_records_per_record_set: long
    :ivar number_of_record_sets: The current number of record sets in this DNS zone.  This is a
     read-only property and any attempt to set this value will be ignored.
    :vartype number_of_record_sets: long
    :ivar name_servers: The name servers for this DNS zone. This is a read-only property and any
     attempt to set this value will be ignored.
    :vartype name_servers: list[str]
    :param zone_type: The type of this DNS zone (Public or Private). Possible values include:
     "Public", "Private". Default value: "Public".
    :type zone_type: str or ~azure.mgmt.dns.v2018_03_01_preview.models.ZoneType
    :param registration_virtual_networks: A list of references to virtual networks that register
     hostnames in this DNS zone. This is a only when ZoneType is Private.
    :type registration_virtual_networks:
     list[~azure.mgmt.dns.v2018_03_01_preview.models.SubResource]
    :param resolution_virtual_networks: A list of references to virtual networks that resolve
     records in this DNS zone. This is a only when ZoneType is Private.
    :type resolution_virtual_networks: list[~azure.mgmt.dns.v2018_03_01_preview.models.SubResource]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'max_number_of_record_sets': {'readonly': True},
        'max_number_of_records_per_record_set': {'readonly': True},
        'number_of_record_sets': {'readonly': True},
        'name_servers': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'max_number_of_record_sets': {'key': 'properties.maxNumberOfRecordSets', 'type': 'long'},
        'max_number_of_records_per_record_set': {'key': 'properties.maxNumberOfRecordsPerRecordSet', 'type': 'long'},
        'number_of_record_sets': {'key': 'properties.numberOfRecordSets', 'type': 'long'},
        'name_servers': {'key': 'properties.nameServers', 'type': '[str]'},
        'zone_type': {'key': 'properties.zoneType', 'type': 'str'},
        'registration_virtual_networks': {'key': 'properties.registrationVirtualNetworks', 'type': '[SubResource]'},
        'resolution_virtual_networks': {'key': 'properties.resolutionVirtualNetworks', 'type': '[SubResource]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Zone, self).__init__(**kwargs)
        self.etag = kwargs.get('etag', None)
        self.max_number_of_record_sets = None
        self.max_number_of_records_per_record_set = None
        self.number_of_record_sets = None
        self.name_servers = None
        self.zone_type = kwargs.get('zone_type', "Public")
        self.registration_virtual_networks = kwargs.get('registration_virtual_networks', None)
        self.resolution_virtual_networks = kwargs.get('resolution_virtual_networks', None)


class ZoneListResult(msrest.serialization.Model):
    """The response to a Zone List or ListAll operation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param value: Information about the DNS zones.
    :type value: list[~azure.mgmt.dns.v2018_03_01_preview.models.Zone]
    :ivar next_link: The continuation token for the next page of results.
    :vartype next_link: str
    """

    _validation = {
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Zone]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ZoneListResult, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = None


class ZoneUpdate(msrest.serialization.Model):
    """Describes a request to update a DNS zone.

    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ZoneUpdate, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
