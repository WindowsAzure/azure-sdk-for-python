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

from ._configuration import AuthorizationManagementClientConfiguration
from .operations import PermissionsOperations
from .operations import RoleDefinitionsOperations
from .operations import ProviderOperationsMetadataOperations
from .operations import GlobalAdministratorOperations
from .operations import RoleAssignmentsOperations
from .operations import ClassicAdministratorsOperations
from . import models


class AuthorizationManagementClient(object):
    """Role based access control provides you a way to apply granular level policy administration down to individual resources or resource groups. These operations enable you to manage role definitions and role assignments. A role definition describes the set of actions that can be performed on resources. A role assignment grants access to Azure Active Directory users.

    :ivar permissions: PermissionsOperations operations
    :vartype permissions: azure.mgmt.authorization.v2015_07_01.operations.PermissionsOperations
    :ivar role_definitions: RoleDefinitionsOperations operations
    :vartype role_definitions: azure.mgmt.authorization.v2015_07_01.operations.RoleDefinitionsOperations
    :ivar provider_operations_metadata: ProviderOperationsMetadataOperations operations
    :vartype provider_operations_metadata: azure.mgmt.authorization.v2015_07_01.operations.ProviderOperationsMetadataOperations
    :ivar global_administrator: GlobalAdministratorOperations operations
    :vartype global_administrator: azure.mgmt.authorization.v2015_07_01.operations.GlobalAdministratorOperations
    :ivar role_assignments: RoleAssignmentsOperations operations
    :vartype role_assignments: azure.mgmt.authorization.v2015_07_01.operations.RoleAssignmentsOperations
    :ivar classic_administrators: ClassicAdministratorsOperations operations
    :vartype classic_administrators: azure.mgmt.authorization.v2015_07_01.operations.ClassicAdministratorsOperations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: The ID of the target subscription.
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
        self._config = AuthorizationManagementClientConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.permissions = PermissionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.role_definitions = RoleDefinitionsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.provider_operations_metadata = ProviderOperationsMetadataOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.global_administrator = GlobalAdministratorOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.role_assignments = RoleAssignmentsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.classic_administrators = ClassicAdministratorsOperations(
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
        # type: () -> AuthorizationManagementClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
