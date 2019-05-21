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


class StorageAccountCreateParameters(Model):
    """The parameters used when creating a storage account.

    All required parameters must be populated in order to send to Azure.

    :param sku: Required. Required. Gets or sets the SKU name.
    :type sku: ~azure.mgmt.storage.v2019_04_01.models.Sku
    :param kind: Required. Required. Indicates the type of storage account.
     Possible values include: 'Storage', 'StorageV2', 'BlobStorage',
     'FileStorage', 'BlockBlobStorage'
    :type kind: str or ~azure.mgmt.storage.v2019_04_01.models.Kind
    :param location: Required. Required. Gets or sets the location of the
     resource. This will be one of the supported and registered Azure Geo
     Regions (e.g. West US, East US, Southeast Asia, etc.). The geo region of a
     resource cannot be changed once it is created, but if an identical geo
     region is specified on update, the request will succeed.
    :type location: str
    :param tags: Gets or sets a list of key value pairs that describe the
     resource. These tags can be used for viewing and grouping this resource
     (across resource groups). A maximum of 15 tags can be provided for a
     resource. Each tag must have a key with a length no greater than 128
     characters and a value with a length no greater than 256 characters.
    :type tags: dict[str, str]
    :param identity: The identity of the resource.
    :type identity: ~azure.mgmt.storage.v2019_04_01.models.Identity
    :param custom_domain: User domain assigned to the storage account. Name is
     the CNAME source. Only one custom domain is supported per storage account
     at this time. To clear the existing custom domain, use an empty string for
     the custom domain name property.
    :type custom_domain: ~azure.mgmt.storage.v2019_04_01.models.CustomDomain
    :param encryption: Provides the encryption settings on the account. If
     left unspecified the account encryption settings will remain the same. The
     default setting is unencrypted.
    :type encryption: ~azure.mgmt.storage.v2019_04_01.models.Encryption
    :param network_rule_set: Network rule set
    :type network_rule_set:
     ~azure.mgmt.storage.v2019_04_01.models.NetworkRuleSet
    :param access_tier: Required for storage accounts where kind =
     BlobStorage. The access tier used for billing. Possible values include:
     'Hot', 'Cool'
    :type access_tier: str or
     ~azure.mgmt.storage.v2019_04_01.models.AccessTier
    :param enable_azure_files_aad_integration: Enables Azure Files AAD
     Integration for SMB if sets to true.
    :type enable_azure_files_aad_integration: bool
    :param enable_https_traffic_only: Allows https traffic only to storage
     service if sets to true.
    :type enable_https_traffic_only: bool
    :param is_hns_enabled: Account HierarchicalNamespace enabled if sets to
     true.
    :type is_hns_enabled: bool
    """

    _validation = {
        'sku': {'required': True},
        'kind': {'required': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'sku': {'key': 'sku', 'type': 'Sku'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'identity': {'key': 'identity', 'type': 'Identity'},
        'custom_domain': {'key': 'properties.customDomain', 'type': 'CustomDomain'},
        'encryption': {'key': 'properties.encryption', 'type': 'Encryption'},
        'network_rule_set': {'key': 'properties.networkAcls', 'type': 'NetworkRuleSet'},
        'access_tier': {'key': 'properties.accessTier', 'type': 'AccessTier'},
        'enable_azure_files_aad_integration': {'key': 'properties.azureFilesAadIntegration', 'type': 'bool'},
        'enable_https_traffic_only': {'key': 'properties.supportsHttpsTrafficOnly', 'type': 'bool'},
        'is_hns_enabled': {'key': 'properties.isHnsEnabled', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(StorageAccountCreateParameters, self).__init__(**kwargs)
        self.sku = kwargs.get('sku', None)
        self.kind = kwargs.get('kind', None)
        self.location = kwargs.get('location', None)
        self.tags = kwargs.get('tags', None)
        self.identity = kwargs.get('identity', None)
        self.custom_domain = kwargs.get('custom_domain', None)
        self.encryption = kwargs.get('encryption', None)
        self.network_rule_set = kwargs.get('network_rule_set', None)
        self.access_tier = kwargs.get('access_tier', None)
        self.enable_azure_files_aad_integration = kwargs.get('enable_azure_files_aad_integration', None)
        self.enable_https_traffic_only = kwargs.get('enable_https_traffic_only', None)
        self.is_hns_enabled = kwargs.get('is_hns_enabled', None)
