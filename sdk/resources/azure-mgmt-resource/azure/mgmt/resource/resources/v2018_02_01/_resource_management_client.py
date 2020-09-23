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

from ._configuration import ResourceManagementClientConfiguration
from .operations import DeploymentsOperations
from .operations import ProvidersOperations
from .operations import ResourcesOperations
from .operations import ResourceGroupsOperations
from .operations import TagsOperations
from .operations import DeploymentOperationsOperations
from . import models


class ResourceManagementClient(object):
    """Provides operations for working with resources and resource groups.

    :ivar deployments: DeploymentsOperations operations
    :vartype deployments: azure.mgmt.resource.resources.v2018_02_01.operations.DeploymentsOperations
    :ivar providers: ProvidersOperations operations
    :vartype providers: azure.mgmt.resource.resources.v2018_02_01.operations.ProvidersOperations
    :ivar resources: ResourcesOperations operations
    :vartype resources: azure.mgmt.resource.resources.v2018_02_01.operations.ResourcesOperations
    :ivar resource_groups: ResourceGroupsOperations operations
    :vartype resource_groups: azure.mgmt.resource.resources.v2018_02_01.operations.ResourceGroupsOperations
    :ivar tags: TagsOperations operations
    :vartype tags: azure.mgmt.resource.resources.v2018_02_01.operations.TagsOperations
    :ivar deployment_operations: DeploymentOperationsOperations operations
    :vartype deployment_operations: azure.mgmt.resource.resources.v2018_02_01.operations.DeploymentOperationsOperations
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
        self._config = ResourceManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.deployments = DeploymentsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.providers = ProvidersOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.resources = ResourcesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.resource_groups = ResourceGroupsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.tags = TagsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.deployment_operations = DeploymentOperationsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> ResourceManagementClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
