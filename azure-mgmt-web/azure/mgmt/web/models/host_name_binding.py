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


class HostNameBinding(Resource):
    """A hostname binding object.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :param name: Resource Name.
    :type name: str
    :param kind: Kind of resource.
    :type kind: str
    :param location: Resource Location.
    :type location: str
    :param type: Resource type.
    :type type: str
    :param tags: Resource tags.
    :type tags: dict
    :param host_name_binding_name: Hostname.
    :type host_name_binding_name: str
    :param site_name: App Service app name.
    :type site_name: str
    :param domain_id: Fully qualified ARM domain resource URI.
    :type domain_id: str
    :param azure_resource_name: Azure resource name.
    :type azure_resource_name: str
    :param azure_resource_type: Azure resource type. Possible values include:
     'Website', 'TrafficManager'
    :type azure_resource_type: str or :class:`AzureResourceType
     <azure.mgmt.web.models.AzureResourceType>`
    :param custom_host_name_dns_record_type: Custom DNS record type. Possible
     values include: 'CName', 'A'
    :type custom_host_name_dns_record_type: str or
     :class:`CustomHostNameDnsRecordType
     <azure.mgmt.web.models.CustomHostNameDnsRecordType>`
    :param host_name_type: Hostname type. Possible values include: 'Verified',
     'Managed'
    :type host_name_type: str or :class:`HostNameType
     <azure.mgmt.web.models.HostNameType>`
    :param ssl_state: SSL type. Possible values include: 'Disabled',
     'SniEnabled', 'IpBasedEnabled'
    :type ssl_state: str or :class:`SslState <azure.mgmt.web.models.SslState>`
    :param thumbprint: SSL certificate thumbprint
    :type thumbprint: str
    :param virtual_ip: Virtual IP address assigned to the hostname if IP based
     SSL is enabled.
    :type virtual_ip: str
    """

    _validation = {
        'id': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'host_name_binding_name': {'key': 'properties.name', 'type': 'str'},
        'site_name': {'key': 'properties.siteName', 'type': 'str'},
        'domain_id': {'key': 'properties.domainId', 'type': 'str'},
        'azure_resource_name': {'key': 'properties.azureResourceName', 'type': 'str'},
        'azure_resource_type': {'key': 'properties.azureResourceType', 'type': 'AzureResourceType'},
        'custom_host_name_dns_record_type': {'key': 'properties.customHostNameDnsRecordType', 'type': 'CustomHostNameDnsRecordType'},
        'host_name_type': {'key': 'properties.hostNameType', 'type': 'HostNameType'},
        'ssl_state': {'key': 'properties.sslState', 'type': 'SslState'},
        'thumbprint': {'key': 'properties.thumbprint', 'type': 'str'},
        'virtual_ip': {'key': 'properties.virtualIP', 'type': 'str'},
    }

    def __init__(self, location, name=None, kind=None, type=None, tags=None, host_name_binding_name=None, site_name=None, domain_id=None, azure_resource_name=None, azure_resource_type=None, custom_host_name_dns_record_type=None, host_name_type=None, ssl_state=None, thumbprint=None, virtual_ip=None):
        super(HostNameBinding, self).__init__(name=name, kind=kind, location=location, type=type, tags=tags)
        self.host_name_binding_name = host_name_binding_name
        self.site_name = site_name
        self.domain_id = domain_id
        self.azure_resource_name = azure_resource_name
        self.azure_resource_type = azure_resource_type
        self.custom_host_name_dns_record_type = custom_host_name_dns_record_type
        self.host_name_type = host_name_type
        self.ssl_state = ssl_state
        self.thumbprint = thumbprint
        self.virtual_ip = virtual_ip
