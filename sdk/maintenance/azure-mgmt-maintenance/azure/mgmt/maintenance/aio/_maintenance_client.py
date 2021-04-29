# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, Optional, TYPE_CHECKING

from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.mgmt.core import AsyncARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from azure.core.credentials_async import AsyncTokenCredential

from ._configuration import MaintenanceClientConfiguration
from .operations import PublicMaintenanceConfigurationsOperations
from .operations import ApplyUpdatesOperations
from .operations import ConfigurationAssignmentsOperations
from .operations import MaintenanceConfigurationsOperations
from .operations import MaintenanceConfigurationsForResourceGroupOperations
from .operations import ApplyUpdateForResourceGroupOperations
from .operations import ConfigurationAssignmentsWithinSubscriptionOperations
from .operations import Operations
from .operations import UpdatesOperations
from .. import models


class MaintenanceClient(object):
    """Maintenance Client.

    :ivar public_maintenance_configurations: PublicMaintenanceConfigurationsOperations operations
    :vartype public_maintenance_configurations: azure.mgmt.maintenance.aio.operations.PublicMaintenanceConfigurationsOperations
    :ivar apply_updates: ApplyUpdatesOperations operations
    :vartype apply_updates: azure.mgmt.maintenance.aio.operations.ApplyUpdatesOperations
    :ivar configuration_assignments: ConfigurationAssignmentsOperations operations
    :vartype configuration_assignments: azure.mgmt.maintenance.aio.operations.ConfigurationAssignmentsOperations
    :ivar maintenance_configurations: MaintenanceConfigurationsOperations operations
    :vartype maintenance_configurations: azure.mgmt.maintenance.aio.operations.MaintenanceConfigurationsOperations
    :ivar maintenance_configurations_for_resource_group: MaintenanceConfigurationsForResourceGroupOperations operations
    :vartype maintenance_configurations_for_resource_group: azure.mgmt.maintenance.aio.operations.MaintenanceConfigurationsForResourceGroupOperations
    :ivar apply_update_for_resource_group: ApplyUpdateForResourceGroupOperations operations
    :vartype apply_update_for_resource_group: azure.mgmt.maintenance.aio.operations.ApplyUpdateForResourceGroupOperations
    :ivar configuration_assignments_within_subscription: ConfigurationAssignmentsWithinSubscriptionOperations operations
    :vartype configuration_assignments_within_subscription: azure.mgmt.maintenance.aio.operations.ConfigurationAssignmentsWithinSubscriptionOperations
    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.maintenance.aio.operations.Operations
    :ivar updates: UpdatesOperations operations
    :vartype updates: azure.mgmt.maintenance.aio.operations.UpdatesOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: Subscription credentials that uniquely identify a Microsoft Azure subscription. The subscription ID forms part of the URI for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
        self,
        credential: "AsyncTokenCredential",
        subscription_id: str,
        base_url: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = MaintenanceClientConfiguration(credential, subscription_id, **kwargs)
        self._client = AsyncARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.public_maintenance_configurations = PublicMaintenanceConfigurationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.apply_updates = ApplyUpdatesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.configuration_assignments = ConfigurationAssignmentsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.maintenance_configurations = MaintenanceConfigurationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.maintenance_configurations_for_resource_group = MaintenanceConfigurationsForResourceGroupOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.apply_update_for_resource_group = ApplyUpdateForResourceGroupOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.configuration_assignments_within_subscription = ConfigurationAssignmentsWithinSubscriptionOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.updates = UpdatesOperations(
            self._client, self._config, self._serialize, self._deserialize)

    async def _send_request(self, http_request: HttpRequest, **kwargs: Any) -> AsyncHttpResponse:
        """Runs the network request through the client's chained policies.

        :param http_request: The network request you want to make. Required.
        :type http_request: ~azure.core.pipeline.transport.HttpRequest
        :keyword bool stream: Whether the response payload will be streamed. Defaults to True.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.pipeline.transport.AsyncHttpResponse
        """
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        http_request.url = self._client.format_url(http_request.url, **path_format_arguments)
        stream = kwargs.pop("stream", True)
        pipeline_response = await self._client._pipeline.run(http_request, stream=stream, **kwargs)
        return pipeline_response.http_response

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> "MaintenanceClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details) -> None:
        await self._client.__aexit__(*exc_details)
