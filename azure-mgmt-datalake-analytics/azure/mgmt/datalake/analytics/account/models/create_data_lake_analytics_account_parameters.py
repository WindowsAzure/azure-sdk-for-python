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


class CreateDataLakeAnalyticsAccountParameters(Model):
    """The parameters to use for creating a Data Lake Analytics account.

    :param location: The resource location.
    :type location: str
    :param tags: The resource tags.
    :type tags: dict[str, str]
    :param default_data_lake_store_account: The default Data Lake Store
     account associated with this account.
    :type default_data_lake_store_account: str
    :param data_lake_store_accounts: The list of Data Lake Store accounts
     associated with this account.
    :type data_lake_store_accounts:
     list[~azure.mgmt.datalake.analytics.account.models.AddDataLakeStoreWithAccountParameters]
    :param storage_accounts: The list of Azure Blob Storage accounts
     associated with this account.
    :type storage_accounts:
     list[~azure.mgmt.datalake.analytics.account.models.AddStorageAccountWithAccountParameters]
    :param compute_policies: The list of compute policies associated with this
     account.
    :type compute_policies:
     list[~azure.mgmt.datalake.analytics.account.models.CreateComputePolicyWithAccountParameters]
    :param firewall_rules: The list of firewall rules associated with this
     account.
    :type firewall_rules:
     list[~azure.mgmt.datalake.analytics.account.models.CreateFirewallRuleWithAccountParameters]
    :param firewall_state: The current state of the IP address firewall for
     this account. Possible values include: 'Enabled', 'Disabled'
    :type firewall_state: str or
     ~azure.mgmt.datalake.analytics.account.models.FirewallState
    :param firewall_allow_azure_ips: The current state of allowing or
     disallowing IPs originating within Azure through the firewall. If the
     firewall is disabled, this is not enforced. Possible values include:
     'Enabled', 'Disabled'
    :type firewall_allow_azure_ips: str or
     ~azure.mgmt.datalake.analytics.account.models.FirewallAllowAzureIpsState
    :param new_tier: The commitment tier for the next month. Possible values
     include: 'Consumption', 'Commitment_100AUHours', 'Commitment_500AUHours',
     'Commitment_1000AUHours', 'Commitment_5000AUHours',
     'Commitment_10000AUHours', 'Commitment_50000AUHours',
     'Commitment_100000AUHours', 'Commitment_500000AUHours'
    :type new_tier: str or
     ~azure.mgmt.datalake.analytics.account.models.TierType
    :param max_job_count: The maximum supported jobs running under the account
     at the same time. Default value: 3 .
    :type max_job_count: int
    :param max_degree_of_parallelism: The maximum supported degree of
     parallelism for this account. Default value: 30 .
    :type max_degree_of_parallelism: int
    :param max_degree_of_parallelism_per_job: The maximum supported degree of
     parallelism per job for this account.
    :type max_degree_of_parallelism_per_job: int
    :param min_priority_per_job: The minimum supported priority per job for
     this account.
    :type min_priority_per_job: int
    :param query_store_retention: The number of days that job metadata is
     retained. Default value: 30 .
    :type query_store_retention: int
    """

    _validation = {
        'location': {'required': True},
        'default_data_lake_store_account': {'required': True},
        'data_lake_store_accounts': {'required': True},
        'max_job_count': {'minimum': 1},
        'max_degree_of_parallelism': {'minimum': 1},
        'max_degree_of_parallelism_per_job': {'minimum': 1},
        'min_priority_per_job': {'minimum': 1},
        'query_store_retention': {'maximum': 180, 'minimum': 1},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'default_data_lake_store_account': {'key': 'properties.defaultDataLakeStoreAccount', 'type': 'str'},
        'data_lake_store_accounts': {'key': 'properties.dataLakeStoreAccounts', 'type': '[AddDataLakeStoreWithAccountParameters]'},
        'storage_accounts': {'key': 'properties.storageAccounts', 'type': '[AddStorageAccountWithAccountParameters]'},
        'compute_policies': {'key': 'properties.computePolicies', 'type': '[CreateComputePolicyWithAccountParameters]'},
        'firewall_rules': {'key': 'properties.firewallRules', 'type': '[CreateFirewallRuleWithAccountParameters]'},
        'firewall_state': {'key': 'properties.firewallState', 'type': 'FirewallState'},
        'firewall_allow_azure_ips': {'key': 'properties.firewallAllowAzureIps', 'type': 'FirewallAllowAzureIpsState'},
        'new_tier': {'key': 'properties.newTier', 'type': 'TierType'},
        'max_job_count': {'key': 'properties.maxJobCount', 'type': 'int'},
        'max_degree_of_parallelism': {'key': 'properties.maxDegreeOfParallelism', 'type': 'int'},
        'max_degree_of_parallelism_per_job': {'key': 'properties.maxDegreeOfParallelismPerJob', 'type': 'int'},
        'min_priority_per_job': {'key': 'properties.minPriorityPerJob', 'type': 'int'},
        'query_store_retention': {'key': 'properties.queryStoreRetention', 'type': 'int'},
    }

    def __init__(self, location, default_data_lake_store_account, data_lake_store_accounts, tags=None, storage_accounts=None, compute_policies=None, firewall_rules=None, firewall_state=None, firewall_allow_azure_ips=None, new_tier=None, max_job_count=3, max_degree_of_parallelism=30, max_degree_of_parallelism_per_job=None, min_priority_per_job=None, query_store_retention=30):
        super(CreateDataLakeAnalyticsAccountParameters, self).__init__()
        self.location = location
        self.tags = tags
        self.default_data_lake_store_account = default_data_lake_store_account
        self.data_lake_store_accounts = data_lake_store_accounts
        self.storage_accounts = storage_accounts
        self.compute_policies = compute_policies
        self.firewall_rules = firewall_rules
        self.firewall_state = firewall_state
        self.firewall_allow_azure_ips = firewall_allow_azure_ips
        self.new_tier = new_tier
        self.max_job_count = max_job_count
        self.max_degree_of_parallelism = max_degree_of_parallelism
        self.max_degree_of_parallelism_per_job = max_degree_of_parallelism_per_job
        self.min_priority_per_job = min_priority_per_job
        self.query_store_retention = query_store_retention
