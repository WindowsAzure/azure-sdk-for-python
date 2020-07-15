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

from msrest.service_client import SDKClient
from msrest import Serializer, Deserializer

from ._configuration import CdnManagementClientConfiguration
from .operations import CdnManagementClientOperationsMixin
from .operations import ProfilesOperations
from .operations import EndpointsOperations
from .operations import OriginsOperations
from .operations import OriginGroupsOperations
from .operations import CustomDomainsOperations
from .operations import ResourceUsageOperations
from .operations import Operations
from .operations import EdgeNodesOperations
from .operations import PoliciesOperations
from .operations import ManagedRuleSetsOperations
from . import models


class CdnManagementClient(CdnManagementClientOperationsMixin, SDKClient):
    """Cdn Management Client

    :ivar config: Configuration for client.
    :vartype config: CdnManagementClientConfiguration

    :ivar profiles: Profiles operations
    :vartype profiles: azure.mgmt.cdn.operations.ProfilesOperations
    :ivar endpoints: Endpoints operations
    :vartype endpoints: azure.mgmt.cdn.operations.EndpointsOperations
    :ivar origins: Origins operations
    :vartype origins: azure.mgmt.cdn.operations.OriginsOperations
    :ivar origin_groups: OriginGroups operations
    :vartype origin_groups: azure.mgmt.cdn.operations.OriginGroupsOperations
    :ivar custom_domains: CustomDomains operations
    :vartype custom_domains: azure.mgmt.cdn.operations.CustomDomainsOperations
    :ivar resource_usage: ResourceUsage operations
    :vartype resource_usage: azure.mgmt.cdn.operations.ResourceUsageOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.cdn.operations.Operations
    :ivar edge_nodes: EdgeNodes operations
    :vartype edge_nodes: azure.mgmt.cdn.operations.EdgeNodesOperations
    :ivar policies: Policies operations
    :vartype policies: azure.mgmt.cdn.operations.PoliciesOperations
    :ivar managed_rule_sets: ManagedRuleSets operations
    :vartype managed_rule_sets: azure.mgmt.cdn.operations.ManagedRuleSetsOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Azure Subscription ID.
    :type subscription_id: str
    :param subscription_id1: Azure Subscription ID.
    :type subscription_id1: str
    :param api_version1: Version of the API to be used with the client
     request. Current version is 2017-04-02.
    :type api_version1: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, subscription_id1, api_version1, base_url=None):

        self.config = CdnManagementClientConfiguration(credentials, subscription_id, subscription_id1, api_version1, base_url)
        super(CdnManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2020-04-15'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.profiles = ProfilesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.endpoints = EndpointsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.origins = OriginsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.origin_groups = OriginGroupsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.custom_domains = CustomDomainsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.resource_usage = ResourceUsageOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
        self.edge_nodes = EdgeNodesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.policies = PoliciesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.managed_rule_sets = ManagedRuleSetsOperations(
            self._client, self.config, self._serialize, self._deserialize)
