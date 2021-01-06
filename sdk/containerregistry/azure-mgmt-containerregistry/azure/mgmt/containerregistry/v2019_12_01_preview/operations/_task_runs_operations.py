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
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse
from azure.core.polling import LROPoller, NoPolling, PollingMethod
from azure.mgmt.core.exceptions import ARMErrorFormat
from azure.mgmt.core.polling.arm_polling import ARMPolling

from .. import models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, Iterable, Optional, TypeVar, Union

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class TaskRunsOperations(object):
    """TaskRunsOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.containerregistry.v2019_12_01_preview.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    def get(
        self,
        resource_group_name,  # type: str
        registry_name,  # type: str
        task_run_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.TaskRun"
        """Gets the detailed information for a given task run.

        :param resource_group_name: The name of the resource group to which the container registry
         belongs.
        :type resource_group_name: str
        :param registry_name: The name of the container registry.
        :type registry_name: str
        :param task_run_name: The name of the task run.
        :type task_run_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: TaskRun, or the result of cls(response)
        :rtype: ~azure.mgmt.containerregistry.v2019_12_01_preview.models.TaskRun
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.TaskRun"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-06-01-preview"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', min_length=1),
            'registryName': self._serialize.url("registry_name", registry_name, 'str', max_length=50, min_length=5, pattern=r'^[a-zA-Z0-9]*$'),
            'taskRunName': self._serialize.url("task_run_name", task_run_name, 'str', max_length=50, min_length=5, pattern=r'^[a-zA-Z0-9-]*$'),
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
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('TaskRun', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerRegistry/registries/{registryName}/taskRuns/{taskRunName}'}  # type: ignore

    def _create_initial(
        self,
        resource_group_name,  # type: str
        registry_name,  # type: str
        task_run_name,  # type: str
        task_run,  # type: "models.TaskRun"
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.TaskRun"
        cls = kwargs.pop('cls', None)  # type: ClsType["models.TaskRun"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-06-01-preview"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self._create_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', min_length=1),
            'registryName': self._serialize.url("registry_name", registry_name, 'str', max_length=50, min_length=5, pattern=r'^[a-zA-Z0-9]*$'),
            'taskRunName': self._serialize.url("task_run_name", task_run_name, 'str', max_length=50, min_length=5, pattern=r'^[a-zA-Z0-9-]*$'),
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
        body_content = self._serialize.body(task_run, 'TaskRun')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        if response.status_code == 200:
            deserialized = self._deserialize('TaskRun', pipeline_response)

        if response.status_code == 201:
            deserialized = self._deserialize('TaskRun', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    _create_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerRegistry/registries/{registryName}/taskRuns/{taskRunName}'}  # type: ignore

    def begin_create(
        self,
        resource_group_name,  # type: str
        registry_name,  # type: str
        task_run_name,  # type: str
        task_run,  # type: "models.TaskRun"
        **kwargs  # type: Any
    ):
        # type: (...) -> LROPoller["models.TaskRun"]
        """Creates a task run for a container registry with the specified parameters.

        :param resource_group_name: The name of the resource group to which the container registry
         belongs.
        :type resource_group_name: str
        :param registry_name: The name of the container registry.
        :type registry_name: str
        :param task_run_name: The name of the task run.
        :type task_run_name: str
        :param task_run: The parameters of a run that needs to scheduled.
        :type task_run: ~azure.mgmt.containerregistry.v2019_12_01_preview.models.TaskRun
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.PollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of LROPoller that returns either TaskRun or the result of cls(response)
        :rtype: ~azure.core.polling.LROPoller[~azure.mgmt.containerregistry.v2019_12_01_preview.models.TaskRun]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, PollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["models.TaskRun"]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = self._create_initial(
                resource_group_name=resource_group_name,
                registry_name=registry_name,
                task_run_name=task_run_name,
                task_run=task_run,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('TaskRun', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        if polling is True: polling_method = ARMPolling(lro_delay,  **kwargs)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        if cont_token:
            return LROPoller.from_continuation_token(
                polling_method=polling_method,
                continuation_token=cont_token,
                client=self._client,
                deserialization_callback=get_long_running_output
            )
        else:
            return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    begin_create.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerRegistry/registries/{registryName}/taskRuns/{taskRunName}'}  # type: ignore

    def _delete_initial(
        self,
        resource_group_name,  # type: str
        registry_name,  # type: str
        task_run_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-06-01-preview"
        accept = "application/json"

        # Construct URL
        url = self._delete_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', min_length=1),
            'registryName': self._serialize.url("registry_name", registry_name, 'str', max_length=50, min_length=5, pattern=r'^[a-zA-Z0-9]*$'),
            'taskRunName': self._serialize.url("task_run_name", task_run_name, 'str', max_length=50, min_length=5, pattern=r'^[a-zA-Z0-9-]*$'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 202, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    _delete_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerRegistry/registries/{registryName}/taskRuns/{taskRunName}'}  # type: ignore

    def begin_delete(
        self,
        resource_group_name,  # type: str
        registry_name,  # type: str
        task_run_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> LROPoller[None]
        """Deletes a specified task run resource.

        :param resource_group_name: The name of the resource group to which the container registry
         belongs.
        :type resource_group_name: str
        :param registry_name: The name of the container registry.
        :type registry_name: str
        :param task_run_name: The name of the task run.
        :type task_run_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.PollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of LROPoller that returns either None or the result of cls(response)
        :rtype: ~azure.core.polling.LROPoller[None]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, PollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = self._delete_initial(
                resource_group_name=resource_group_name,
                registry_name=registry_name,
                task_run_name=task_run_name,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            if cls:
                return cls(pipeline_response, None, {})

        if polling is True: polling_method = ARMPolling(lro_delay,  **kwargs)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        if cont_token:
            return LROPoller.from_continuation_token(
                polling_method=polling_method,
                continuation_token=cont_token,
                client=self._client,
                deserialization_callback=get_long_running_output
            )
        else:
            return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    begin_delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerRegistry/registries/{registryName}/taskRuns/{taskRunName}'}  # type: ignore

    def _update_initial(
        self,
        resource_group_name,  # type: str
        registry_name,  # type: str
        task_run_name,  # type: str
        update_parameters,  # type: "models.TaskRunUpdateParameters"
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.TaskRun"
        cls = kwargs.pop('cls', None)  # type: ClsType["models.TaskRun"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-06-01-preview"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self._update_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', min_length=1),
            'registryName': self._serialize.url("registry_name", registry_name, 'str', max_length=50, min_length=5, pattern=r'^[a-zA-Z0-9]*$'),
            'taskRunName': self._serialize.url("task_run_name", task_run_name, 'str', max_length=50, min_length=5, pattern=r'^[a-zA-Z0-9-]*$'),
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
        body_content = self._serialize.body(update_parameters, 'TaskRunUpdateParameters')
        body_content_kwargs['content'] = body_content
        request = self._client.patch(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        if response.status_code == 200:
            deserialized = self._deserialize('TaskRun', pipeline_response)

        if response.status_code == 201:
            deserialized = self._deserialize('TaskRun', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    _update_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerRegistry/registries/{registryName}/taskRuns/{taskRunName}'}  # type: ignore

    def begin_update(
        self,
        resource_group_name,  # type: str
        registry_name,  # type: str
        task_run_name,  # type: str
        update_parameters,  # type: "models.TaskRunUpdateParameters"
        **kwargs  # type: Any
    ):
        # type: (...) -> LROPoller["models.TaskRun"]
        """Updates a task run with the specified parameters.

        :param resource_group_name: The name of the resource group to which the container registry
         belongs.
        :type resource_group_name: str
        :param registry_name: The name of the container registry.
        :type registry_name: str
        :param task_run_name: The name of the task run.
        :type task_run_name: str
        :param update_parameters: The parameters for updating a task run.
        :type update_parameters: ~azure.mgmt.containerregistry.v2019_12_01_preview.models.TaskRunUpdateParameters
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.PollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of LROPoller that returns either TaskRun or the result of cls(response)
        :rtype: ~azure.core.polling.LROPoller[~azure.mgmt.containerregistry.v2019_12_01_preview.models.TaskRun]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, PollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["models.TaskRun"]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = self._update_initial(
                resource_group_name=resource_group_name,
                registry_name=registry_name,
                task_run_name=task_run_name,
                update_parameters=update_parameters,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('TaskRun', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        if polling is True: polling_method = ARMPolling(lro_delay,  **kwargs)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        if cont_token:
            return LROPoller.from_continuation_token(
                polling_method=polling_method,
                continuation_token=cont_token,
                client=self._client,
                deserialization_callback=get_long_running_output
            )
        else:
            return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    begin_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerRegistry/registries/{registryName}/taskRuns/{taskRunName}'}  # type: ignore

    def get_details(
        self,
        resource_group_name,  # type: str
        registry_name,  # type: str
        task_run_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "models.TaskRun"
        """Gets the detailed information for a given task run that includes all secrets.

        :param resource_group_name: The name of the resource group to which the container registry
         belongs.
        :type resource_group_name: str
        :param registry_name: The name of the container registry.
        :type registry_name: str
        :param task_run_name: The name of the task run.
        :type task_run_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: TaskRun, or the result of cls(response)
        :rtype: ~azure.mgmt.containerregistry.v2019_12_01_preview.models.TaskRun
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.TaskRun"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-06-01-preview"
        accept = "application/json"

        # Construct URL
        url = self.get_details.metadata['url']  # type: ignore
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', min_length=1),
            'registryName': self._serialize.url("registry_name", registry_name, 'str', max_length=50, min_length=5, pattern=r'^[a-zA-Z0-9]*$'),
            'taskRunName': self._serialize.url("task_run_name", task_run_name, 'str', max_length=50, min_length=5, pattern=r'^[a-zA-Z0-9-]*$'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize(models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('TaskRun', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_details.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerRegistry/registries/{registryName}/taskRuns/{taskRunName}/listDetails'}  # type: ignore

    def list(
        self,
        resource_group_name,  # type: str
        registry_name,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["models.TaskRunListResult"]
        """Lists all the task runs for a specified container registry.

        :param resource_group_name: The name of the resource group to which the container registry
         belongs.
        :type resource_group_name: str
        :param registry_name: The name of the container registry.
        :type registry_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either TaskRunListResult or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.mgmt.containerregistry.v2019_12_01_preview.models.TaskRunListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.TaskRunListResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2019-06-01-preview"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']  # type: ignore
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', min_length=1),
                    'registryName': self._serialize.url("registry_name", registry_name, 'str', max_length=50, min_length=5, pattern=r'^[a-zA-Z0-9]*$'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('TaskRunListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize(models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerRegistry/registries/{registryName}/taskRuns'}  # type: ignore
