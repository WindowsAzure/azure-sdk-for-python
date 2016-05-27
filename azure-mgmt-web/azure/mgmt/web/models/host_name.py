# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class HostName(Model):
    """
    Details of a hostname derived from a domain

    :param name: Name of the hostname
    :type name: str
    :param site_names: List of sites the hostname is assigned to. This list
     will have more than one site only if the hostname is pointing to a
     Traffic Manager
    :type site_names: list of str
    :param azure_resource_name: Name of the Azure resource the hostname is
     assigned to. If it is assigned to a traffic manager then it will be the
     traffic manager name otherwise it will be the website name
    :type azure_resource_name: str
    :param azure_resource_type: Type of the Azure resource the hostname is
     assigned to. Possible values include: 'Website', 'TrafficManager'
    :type azure_resource_type: str or :class:`AzureResourceType
     <websitemanagementclient.models.AzureResourceType>`
    :param custom_host_name_dns_record_type: Type of the Dns record. Possible
     values include: 'CName', 'A'
    :type custom_host_name_dns_record_type: str or
     :class:`CustomHostNameDnsRecordType
     <websitemanagementclient.models.CustomHostNameDnsRecordType>`
    :param host_name_type: Type of the hostname. Possible values include:
     'Verified', 'Managed'
    :type host_name_type: str or :class:`HostNameType
     <websitemanagementclient.models.HostNameType>`
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
        self.name = name
        self.site_names = site_names
        self.azure_resource_name = azure_resource_name
        self.azure_resource_type = azure_resource_type
        self.custom_host_name_dns_record_type = custom_host_name_dns_record_type
        self.host_name_type = host_name_type
