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

from ._configuration import PolicyInsightsClientConfiguration
from .operations import PolicyTrackedResourcesOperations
from .operations import RemediationsOperations
from .operations import PolicyEventsOperations
from .operations import PolicyStatesOperations
from .operations import Operations
from . import models


class PolicyInsightsClient(SDKClient):
    """PolicyInsightsClient

    :ivar config: Configuration for client.
    :vartype config: PolicyInsightsClientConfiguration

    :ivar policy_tracked_resources: PolicyTrackedResources operations
    :vartype policy_tracked_resources: azure.mgmt.policyinsights.operations.PolicyTrackedResourcesOperations
    :ivar remediations: Remediations operations
    :vartype remediations: azure.mgmt.policyinsights.operations.RemediationsOperations
    :ivar policy_events: PolicyEvents operations
    :vartype policy_events: azure.mgmt.policyinsights.operations.PolicyEventsOperations
    :ivar policy_states: PolicyStates operations
    :vartype policy_states: azure.mgmt.policyinsights.operations.PolicyStatesOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.policyinsights.operations.Operations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, base_url=None):

        self.config = PolicyInsightsClientConfiguration(credentials, base_url)
        super(PolicyInsightsClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.policy_tracked_resources = PolicyTrackedResourcesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.remediations = RemediationsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.policy_events = PolicyEventsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.policy_states = PolicyStatesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self.config, self._serialize, self._deserialize)
