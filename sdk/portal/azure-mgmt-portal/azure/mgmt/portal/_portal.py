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

from ._configuration import PortalConfiguration
from .operations import Operations
from .operations import DashboardsOperations
from .operations import TenantConfigurationsOperations
from .operations import ListTenantConfigurationViolationsOperations
from . import models


class Portal(object):
    """Allows creation and deletion of Azure Shared Dashboards.

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.portal.operations.Operations
    :ivar dashboards: DashboardsOperations operations
    :vartype dashboards: azure.mgmt.portal.operations.DashboardsOperations
    :ivar tenant_configurations: TenantConfigurationsOperations operations
    :vartype tenant_configurations: azure.mgmt.portal.operations.TenantConfigurationsOperations
    :ivar list_tenant_configuration_violations: ListTenantConfigurationViolationsOperations operations
    :vartype list_tenant_configuration_violations: azure.mgmt.portal.operations.ListTenantConfigurationViolationsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: The Azure subscription ID. This is a GUID-formatted string (e.g. 00000000-0000-0000-0000-000000000000).
    :type subscription_id: str
    :param str base_url: Service URL
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
        self._config = PortalConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)
        self.dashboards = DashboardsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.tenant_configurations = TenantConfigurationsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.list_tenant_configuration_violations = ListTenantConfigurationViolationsOperations(
            self._client, self._config, self._serialize, self._deserialize)

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> Portal
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
