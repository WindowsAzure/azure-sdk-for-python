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


class HostName(Model):
    """Details of a hostname derived from a domain.

    :param name: Name of the hostname.
    :type name: str
    :param site_names: List of apps the hostname is assigned to. This list
     will have more than one app only if the hostname is pointing to a Traffic
     Manager.
    :type site_names: list[str]
    :param azure_resource_name: Name of the Azure resource the hostname is
     assigned to. If it is assigned to a Traffic Manager then it will be the
     Traffic Manager name otherwise it will be the app name.
    :type azure_resource_name: str
    :param azure_resource_type: Type of the Azure resource the hostname is
     assigned to. Possible values include: 'Website', 'TrafficManager'
    :type azure_resource_type: str or ~azure.mgmt.web.models.AzureResourceType
    :param custom_host_name_dns_record_type: Type of the DNS record. Possible
     values include: 'CName', 'A'
    :type custom_host_name_dns_record_type: str or
     ~azure.mgmt.web.models.CustomHostNameDnsRecordType
    :param host_name_type: Type of the hostname. Possible values include:
     'Verified', 'Managed'
    :type host_name_type: str or ~azure.mgmt.web.models.HostNameType
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'site_names': {'key': 'siteNames', 'type': '[str]'},
        'azure_resource_name': {'key': 'azureResourceName', 'type': 'str'},
        'azure_resource_type': {'key': 'azureResourceType', 'type': 'AzureResourceType'},
        'custom_host_name_dns_record_type': {'key': 'customHostNameDnsRecordType', 'type': 'CustomHostNameDnsRecordType'},
        'host_name_type': {'key': 'hostNameType', 'type': 'HostNameType'},
    }

    def __init__(self, name=None, site_names=None, azure_resource_name=None, azure_resource_type=None, custom_host_name_dns_record_type=None, host_name_type=None):
        super(HostName, self).__init__()
        self.name = name
        self.site_names = site_names
        self.azure_resource_name = azure_resource_name
        self.azure_resource_type = azure_resource_type
        self.custom_host_name_dns_record_type = custom_host_name_dns_record_type
        self.host_name_type = host_name_type
