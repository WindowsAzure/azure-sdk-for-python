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


class RecordSet(Model):
    """Describes a DNS record set (a collection of DNS records with the same name
    and type).

    Variables are only populated by the server, and will be ignored when
    sending a request.

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
    :ivar provisioning_state: provisioning State of the record set.
    :vartype provisioning_state: str
    :param target_resource:
    :type target_resource: ~azure.mgmt.dns.v2018_05_01.models.SubResource
    :param arecords: The list of A records in the record set.
    :type arecords: list[~azure.mgmt.dns.v2018_05_01.models.ARecord]
    :param aaaa_records: The list of AAAA records in the record set.
    :type aaaa_records: list[~azure.mgmt.dns.v2018_05_01.models.AaaaRecord]
    :param mx_records: The list of MX records in the record set.
    :type mx_records: list[~azure.mgmt.dns.v2018_05_01.models.MxRecord]
    :param ns_records: The list of NS records in the record set.
    :type ns_records: list[~azure.mgmt.dns.v2018_05_01.models.NsRecord]
    :param ptr_records: The list of PTR records in the record set.
    :type ptr_records: list[~azure.mgmt.dns.v2018_05_01.models.PtrRecord]
    :param srv_records: The list of SRV records in the record set.
    :type srv_records: list[~azure.mgmt.dns.v2018_05_01.models.SrvRecord]
    :param txt_records: The list of TXT records in the record set.
    :type txt_records: list[~azure.mgmt.dns.v2018_05_01.models.TxtRecord]
    :param cname_record: The CNAME record in the  record set.
    :type cname_record: ~azure.mgmt.dns.v2018_05_01.models.CnameRecord
    :param soa_record: The SOA record in the record set.
    :type soa_record: ~azure.mgmt.dns.v2018_05_01.models.SoaRecord
    :param caa_records: The list of CAA records in the record set.
    :type caa_records: list[~azure.mgmt.dns.v2018_05_01.models.CaaRecord]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'fqdn': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'metadata': {'key': 'properties.metadata', 'type': '{str}'},
        'ttl': {'key': 'properties.TTL', 'type': 'long'},
        'fqdn': {'key': 'properties.fqdn', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'target_resource': {'key': 'properties.targetResource', 'type': 'SubResource'},
        'arecords': {'key': 'properties.ARecords', 'type': '[ARecord]'},
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

    def __init__(self, **kwargs):
        super(RecordSet, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.etag = kwargs.get('etag', None)
        self.metadata = kwargs.get('metadata', None)
        self.ttl = kwargs.get('ttl', None)
        self.fqdn = None
        self.provisioning_state = None
        self.target_resource = kwargs.get('target_resource', None)
        self.arecords = kwargs.get('arecords', None)
        self.aaaa_records = kwargs.get('aaaa_records', None)
        self.mx_records = kwargs.get('mx_records', None)
        self.ns_records = kwargs.get('ns_records', None)
        self.ptr_records = kwargs.get('ptr_records', None)
        self.srv_records = kwargs.get('srv_records', None)
        self.txt_records = kwargs.get('txt_records', None)
        self.cname_record = kwargs.get('cname_record', None)
        self.soa_record = kwargs.get('soa_record', None)
        self.caa_records = kwargs.get('caa_records', None)
