# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse

from .. import models as _models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, List, Optional, TypeVar

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class RoleAssignmentsOperations(object):
    """RoleAssignmentsOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.synapse.accesscontrol.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = _models

    def __init__(self, client, config, serializer, deserializer):
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    def check_principal_access(
        self,
        subject,  # type: "_models.SubjectInfo"
        actions,  # type: List["_models.RequiredAction"]
        scope,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.CheckPrincipalAccessResponse"
        """Check if the given principalId has access to perform list of actions at a given scope.

        :param subject: Subject details.
        :type subject: ~azure.synapse.accesscontrol.models.SubjectInfo
        :param actions: List of actions.
        :type actions: list[~azure.synapse.accesscontrol.models.RequiredAction]
        :param scope: Scope at which the check access is done.
        :type scope: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: CheckPrincipalAccessResponse, or the result of cls(response)
        :rtype: ~azure.synapse.accesscontrol.models.CheckPrincipalAccessResponse
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.CheckPrincipalAccessResponse"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        _request = _models.CheckPrincipalAccessRequest(subject=subject, actions=actions, scope=scope)
        api_version = "2020-08-01-preview"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json, text/json"

        # Construct URL
        url = self.check_principal_access.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(_request, 'CheckPrincipalAccessRequest')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorContract, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('CheckPrincipalAccessResponse', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    check_principal_access.metadata = {'url': '/checkAccessSynapseRbac'}  # type: ignore

    def list_role_assignments(
        self,
        role_id=None,  # type: Optional[str]
        principal_id=None,  # type: Optional[str]
        scope=None,  # type: Optional[str]
        continuation_token_parameter=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.RoleAssignmentDetailsList"
        """List role assignments.

        :param role_id: Synapse Built-In Role Id.
        :type role_id: str
        :param principal_id: Object ID of the AAD principal or security-group.
        :type principal_id: str
        :param scope: Scope of the Synapse Built-in Role.
        :type scope: str
        :param continuation_token_parameter: Continuation token.
        :type continuation_token_parameter: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: RoleAssignmentDetailsList, or the result of cls(response)
        :rtype: ~azure.synapse.accesscontrol.models.RoleAssignmentDetailsList
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.RoleAssignmentDetailsList"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-08-01-preview"
        accept = "application/json, text/json"

        # Construct URL
        url = self.list_role_assignments.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
        if role_id is not None:
            query_parameters['roleId'] = self._serialize.query("role_id", role_id, 'str')
        if principal_id is not None:
            query_parameters['principalId'] = self._serialize.query("principal_id", principal_id, 'str')
        if scope is not None:
            query_parameters['scope'] = self._serialize.query("scope", scope, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if continuation_token_parameter is not None:
            header_parameters['x-ms-continuation'] = self._serialize.header("continuation_token_parameter", continuation_token_parameter, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorContract, response)
            raise HttpResponseError(response=response, model=error)

        response_headers = {}
        response_headers['x-ms-continuation']=self._deserialize('str', response.headers.get('x-ms-continuation'))
        deserialized = self._deserialize('RoleAssignmentDetailsList', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    list_role_assignments.metadata = {'url': '/roleAssignments'}  # type: ignore

    def create_role_assignment(
        self,
        role_assignment_id,  # type: str
        role_id,  # type: str
        principal_id,  # type: str
        scope,  # type: str
        principal_type=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.RoleAssignmentDetails"
        """Create role assignment.

        :param role_assignment_id: The ID of the role assignment.
        :type role_assignment_id: str
        :param role_id: Role ID of the Synapse Built-In Role.
        :type role_id: str
        :param principal_id: Object ID of the AAD principal or security-group.
        :type principal_id: str
        :param scope: Scope at which the role assignment is created.
        :type scope: str
        :param principal_type: Type of the principal Id: User, Group or ServicePrincipal.
        :type principal_type: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: RoleAssignmentDetails, or the result of cls(response)
        :rtype: ~azure.synapse.accesscontrol.models.RoleAssignmentDetails
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.RoleAssignmentDetails"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        _request = _models.RoleAssignmentRequest(role_id=role_id, principal_id=principal_id, scope=scope, principal_type=principal_type)
        api_version = "2020-08-01-preview"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json, text/json"

        # Construct URL
        url = self.create_role_assignment.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'roleAssignmentId': self._serialize.url("role_assignment_id", role_assignment_id, 'str', min_length=1),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(_request, 'RoleAssignmentRequest')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorContract, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('RoleAssignmentDetails', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create_role_assignment.metadata = {'url': '/roleAssignments/{roleAssignmentId}'}  # type: ignore

    def get_role_assignment_by_id(
        self,
        role_assignment_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.RoleAssignmentDetails"
        """Get role assignment by role assignment Id.

        :param role_assignment_id: The ID of the role assignment.
        :type role_assignment_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: RoleAssignmentDetails, or the result of cls(response)
        :rtype: ~azure.synapse.accesscontrol.models.RoleAssignmentDetails
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.RoleAssignmentDetails"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-08-01-preview"
        accept = "application/json, text/json"

        # Construct URL
        url = self.get_role_assignment_by_id.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'roleAssignmentId': self._serialize.url("role_assignment_id", role_assignment_id, 'str', min_length=1),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorContract, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('RoleAssignmentDetails', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_role_assignment_by_id.metadata = {'url': '/roleAssignments/{roleAssignmentId}'}  # type: ignore

    def delete_role_assignment_by_id(
        self,
        role_assignment_id,  # type: str
        scope=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Delete role assignment by role assignment Id.

        :param role_assignment_id: The ID of the role assignment.
        :type role_assignment_id: str
        :param scope: Scope of the Synapse Built-in Role.
        :type scope: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: None, or the result of cls(response)
        :rtype: None
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-08-01-preview"
        accept = "application/json, text/json"

        # Construct URL
        url = self.delete_role_assignment_by_id.metadata['url']  # type: ignore
        path_format_arguments = {
            'endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'roleAssignmentId': self._serialize.url("role_assignment_id", role_assignment_id, 'str', min_length=1),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')
        if scope is not None:
            query_parameters['scope'] = self._serialize.query("scope", scope, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorContract, response)
            raise HttpResponseError(response=response, model=error)

        if cls:
            return cls(pipeline_response, None, {})

    delete_role_assignment_by_id.metadata = {'url': '/roleAssignments/{roleAssignmentId}'}  # type: ignore
