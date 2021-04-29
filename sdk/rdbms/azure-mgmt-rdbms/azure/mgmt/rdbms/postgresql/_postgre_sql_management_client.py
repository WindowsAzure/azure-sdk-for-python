# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import TYPE_CHECKING

from azure.mgmt.core import ARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Optional

    from azure.core.credentials import TokenCredential
    from azure.core.pipeline.transport import HttpRequest, HttpResponse

from ._configuration import PostgreSQLManagementClientConfiguration
from .operations import ServersOperations
from .operations import ReplicasOperations
from .operations import FirewallRulesOperations
from .operations import VirtualNetworkRulesOperations
from .operations import DatabasesOperations
from .operations import ConfigurationsOperations
from .operations import ServerParametersOperations
from .operations import LogFilesOperations
from .operations import ServerAdministratorsOperations
from .operations import RecoverableServersOperations
from .operations import ServerBasedPerformanceTierOperations
from .operations import LocationBasedPerformanceTierOperations
from .operations import CheckNameAvailabilityOperations
from .operations import Operations
from .operations import ServerSecurityAlertPoliciesOperations
from .operations import PrivateEndpointConnectionsOperations
from .operations import PrivateLinkResourcesOperations
from .operations import ServerKeysOperations
from . import models


class PostgreSQLManagementClient(object):
    """The Microsoft Azure management API provides create, read, update, and delete functionality for Azure PostgreSQL resources including servers, databases, firewall rules, VNET rules, security alert policies, log files and configurations with new business model.

    :ivar servers: ServersOperations operations
    :vartype servers: azure.mgmt.rdbms.postgresql.operations.ServersOperations
    :ivar replicas: ReplicasOperations operations
    :vartype replicas: azure.mgmt.rdbms.postgresql.operations.ReplicasOperations
    :ivar firewall_rules: FirewallRulesOperations operations
    :vartype firewall_rules: azure.mgmt.rdbms.postgresql.operations.FirewallRulesOperations
    :ivar virtual_network_rules: VirtualNetworkRulesOperations operations
    :vartype virtual_network_rules: azure.mgmt.rdbms.postgresql.operations.VirtualNetworkRulesOperations
    :ivar databases: DatabasesOperations operations
    :vartype databases: azure.mgmt.rdbms.postgresql.operations.DatabasesOperations
    :ivar configurations: ConfigurationsOperations operations
    :vartype configurations: azure.mgmt.rdbms.postgresql.operations.ConfigurationsOperations
    :ivar server_parameters: ServerParametersOperations operations
    :vartype server_parameters: azure.mgmt.rdbms.postgresql.operations.ServerParametersOperations
    :ivar log_files: LogFilesOperations operations
    :vartype log_files: azure.mgmt.rdbms.postgresql.operations.LogFilesOperations
    :ivar server_administrators: ServerAdministratorsOperations operations
    :vartype server_administrators: azure.mgmt.rdbms.postgresql.operations.ServerAdministratorsOperations
    :ivar recoverable_servers: RecoverableServersOperations operations
    :vartype recoverable_servers: azure.mgmt.rdbms.postgresql.operations.RecoverableServersOperations
    :ivar server_based_performance_tier: ServerBasedPerformanceTierOperations operations
    :vartype server_based_performance_tier: azure.mgmt.rdbms.postgresql.operations.ServerBasedPerformanceTierOperations
    :ivar location_based_performance_tier: LocationBasedPerformanceTierOperations operations
    :vartype location_based_performance_tier: azure.mgmt.rdbms.postgresql.operations.LocationBasedPerformanceTierOperations
    :ivar check_name_availability: CheckNameAvailabilityOperations operations
    :vartype check_name_availability: azure.mgmt.rdbms.postgresql.operations.CheckNameAvailabilityOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.rdbms.postgresql.operations.Operations
    :ivar server_security_alert_policies: ServerSecurityAlertPoliciesOperations operations
    :vartype server_security_alert_policies: azure.mgmt.rdbms.postgresql.operations.ServerSecurityAlertPoliciesOperations
    :ivar private_endpoint_connections: PrivateEndpointConnectionsOperations operations
    :vartype private_endpoint_connections: azure.mgmt.rdbms.postgresql.operations.PrivateEndpointConnectionsOperations
    :ivar private_link_resources: PrivateLinkResourcesOperations operations
    :vartype private_link_resources: azure.mgmt.rdbms.postgresql.operations.PrivateLinkResourcesOperations
    :ivar server_keys: ServerKeysOperations operations
    :vartype server_keys: azure.mgmt.rdbms.postgresql.operations.ServerKeysOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: The ID of the target subscription.
    :type subscription_id: str
    :param str base_url: Service URL
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        subscription_id,  # type: str
        base_url=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = PostgreSQLManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.servers = ServersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.replicas = ReplicasOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.firewall_rules = FirewallRulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.virtual_network_rules = VirtualNetworkRulesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.databases = DatabasesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.configurations = ConfigurationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.server_parameters = ServerParametersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.log_files = LogFilesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.server_administrators = ServerAdministratorsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.recoverable_servers = RecoverableServersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.server_based_performance_tier = ServerBasedPerformanceTierOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.location_based_performance_tier = LocationBasedPerformanceTierOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.check_name_availability = CheckNameAvailabilityOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.server_security_alert_policies = ServerSecurityAlertPoliciesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.private_endpoint_connections = PrivateEndpointConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.private_link_resources = PrivateLinkResourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.server_keys = ServerKeysOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def _send_request(self, http_request, **kwargs):
        # type: (HttpRequest, Any) -> HttpResponse
        """Runs the network request through the client's chained policies.

        :param http_request: The network request you want to make. Required.
        :type http_request: ~azure.core.pipeline.transport.HttpRequest
        :keyword bool stream: Whether the response payload will be streamed. Defaults to True.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.pipeline.transport.HttpResponse
        """
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
        }
        http_request.url = self._client.format_url(http_request.url, **path_format_arguments)
        stream = kwargs.pop("stream", True)
        pipeline_response = self._client._pipeline.run(http_request, stream=stream, **kwargs)
        return pipeline_response.http_response

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> PostgreSQLManagementClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
