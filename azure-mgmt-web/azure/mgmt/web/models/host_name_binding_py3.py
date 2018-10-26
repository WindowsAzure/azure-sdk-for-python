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

from .proxy_only_resource_py3 import ProxyOnlyResource


class HostNameBinding(ProxyOnlyResource):
    """A hostname binding object.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :param site_name: App Service app name.
    :type site_name: str
    :param domain_id: Fully qualified ARM domain resource URI.
    :type domain_id: str
    :param azure_resource_name: Azure resource name.
    :type azure_resource_name: str
    :param azure_resource_type: Azure resource type. Possible values include:
     'Website', 'TrafficManager'
    :type azure_resource_type: str or ~azure.mgmt.web.models.AzureResourceType
    :param custom_host_name_dns_record_type: Custom DNS record type. Possible
     values include: 'CName', 'A'
    :type custom_host_name_dns_record_type: str or
     ~azure.mgmt.web.models.CustomHostNameDnsRecordType
    :param host_name_type: Hostname type. Possible values include: 'Verified',
     'Managed'
    :type host_name_type: str or ~azure.mgmt.web.models.HostNameType
    :param ssl_state: SSL type. Possible values include: 'Disabled',
     'SniEnabled', 'IpBasedEnabled'
    :type ssl_state: str or ~azure.mgmt.web.models.SslState
    :param thumbprint: SSL certificate thumbprint
    :type thumbprint: str
    :ivar virtual_ip: Virtual IP address assigned to the hostname if IP based
     SSL is enabled.
    :vartype virtual_ip: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'virtual_ip': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
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

    def __init__(self, *, kind: str=None, site_name: str=None, domain_id: str=None, azure_resource_name: str=None, azure_resource_type=None, custom_host_name_dns_record_type=None, host_name_type=None, ssl_state=None, thumbprint: str=None, **kwargs) -> None:
        super(HostNameBinding, self).__init__(kind=kind, **kwargs)
        self.site_name = site_name
        self.domain_id = domain_id
        self.azure_resource_name = azure_resource_name
        self.azure_resource_type = azure_resource_type
        self.custom_host_name_dns_record_type = custom_host_name_dns_record_type
        self.host_name_type = host_name_type
        self.ssl_state = ssl_state
        self.thumbprint = thumbprint
        self.virtual_ip = None
