# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, Callable, Dict, Generic, Optional, TYPE_CHECKING, TypeVar, Union
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse
from azure.core.polling import AsyncLROPoller, AsyncNoPolling, AsyncPollingMethod
from azure.core.polling.async_base_polling import AsyncLROBasePolling
from azure.farmbeats.core.rest import HttpRequest

from ...rest import farm_operations as rest_farm_operations

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class FarmOperationsOperations:
    """FarmOperationsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    def __init__(self, client, config, serializer, deserializer) -> None:
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    async def _create_data_ingestion_jo_initial(
        self,
        job_id: str,
        *,
        job: Any = None,
        **kwargs: Any
    ) -> Any:
        cls = kwargs.pop('cls', None)  # type: ClsType[Any]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        content_type = kwargs.pop("content_type", "application/json")
        if job is not None:
            json = self._serialize.body(job, 'FarmOperationDataIngestionJob')
        else:
            json = None


        request = rest_farm_operations.build_create_data_ingestion_job_request_initial(
            job_id=job_id,
            json=json,
            content_type=content_type,
            template_url=self._create_data_ingestion_jo_initial.metadata['url'],
            **kwargs
        )._internal_request
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        request.url = self._client.format_url(request.url, **path_format_arguments)
        kwargs.pop("content_type", None)

        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('FarmOperationDataIngestionJob', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized

    _create_data_ingestion_jo_initial.metadata = {'url': '/farm-operations/ingest-data/{jobId}'}  # type: ignore

    async def begin_create_data_ingestion_job(
        self,
        job_id: str,
        *,
        job: Any = None,
        **kwargs: Any
    ) -> AsyncLROPoller[Any]:
        """Create a farm operation data ingestion job.

        :param job_id: Job Id supplied by user.
        :type job_id: str
        :keyword job: Job parameters supplied by user.
        :paramtype job: Any
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: Pass in True if you'd like the AsyncLROBasePolling polling method,
         False for no polling, or your own initialized polling object for a personal polling strategy.
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either Any or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[Any]
        :raises ~azure.core.exceptions.HttpResponseError:

        Example:
            .. code-block:: python

                # JSON input template you can fill out and use as your `json` input.
                json = {
                    "authProviderId": "str",
                    "createdDateTime": "datetime (optional)",
                    "description": "str (optional)",
                    "durationInSeconds": "str (optional)",
                    "endTime": "datetime (optional)",
                    "farmerId": "str",
                    "id": "str (optional)",
                    "lastActionDateTime": "datetime (optional)",
                    "message": "str (optional)",
                    "name": "str (optional)",
                    "operations": [
                        "str (optional)"
                    ],
                    "properties": {
                        "str": "object (optional)"
                    },
                    "startTime": "datetime (optional)",
                    "startYear": "int",
                    "status": "str (optional)"
                }

        """
        polling = kwargs.pop('polling', False)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType[Any]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = await self._create_data_ingestion_jo_initial(
                job_id=job_id,

                job=job,


                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            deserialized = self._deserialize('FarmOperationDataIngestionJob', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, {})
            return deserialized

        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }

        if polling is True: polling_method = AsyncLROBasePolling(lro_delay, lro_options={'final-state-via': 'location'}, path_format_arguments=path_format_arguments,  **kwargs)
        elif polling is False: polling_method = AsyncNoPolling()
        else: polling_method = polling
        if cont_token:
            return AsyncLROPoller.from_continuation_token(
                polling_method=polling_method,
                continuation_token=cont_token,
                client=self._client,
                deserialization_callback=get_long_running_output
            )
        else:
            return AsyncLROPoller(self._client, raw_result, get_long_running_output, polling_method)
    begin_create_data_ingestion_job.metadata = {'url': '/farm-operations/ingest-data/{jobId}'}  # type: ignore


    async def get_data_ingestion_job_details(
        self,
        job_id: str,
        **kwargs: Any
    ) -> Any:
        """Get a farm operation data ingestion job.

        :param job_id: Id of the job.
        :type job_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Any, or the result of cls(response)
        :rtype: Any
        :raises: ~azure.core.exceptions.HttpResponseError

        Example:
            .. code-block:: python

                # response body for status code(s): 200
                response_body == {
                    "authProviderId": "str",
                    "createdDateTime": "datetime (optional)",
                    "description": "str (optional)",
                    "durationInSeconds": "str (optional)",
                    "endTime": "datetime (optional)",
                    "farmerId": "str",
                    "id": "str (optional)",
                    "lastActionDateTime": "datetime (optional)",
                    "message": "str (optional)",
                    "name": "str (optional)",
                    "operations": [
                        "str (optional)"
                    ],
                    "properties": {
                        "str": "object (optional)"
                    },
                    "startTime": "datetime (optional)",
                    "startYear": "int",
                    "status": "str (optional)"
                }

        """
        cls = kwargs.pop('cls', None)  # type: ClsType[Any]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        request = rest_farm_operations.build_get_data_ingestion_job_details_request(
            job_id=job_id,
            template_url=self.get_data_ingestion_job_details.metadata['url'],
            **kwargs
        )._internal_request
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        request.url = self._client.format_url(request.url, **path_format_arguments)
        kwargs.pop("content_type", None)

        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)

        deserialized = self._deserialize('FarmOperationDataIngestionJob', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized

    get_data_ingestion_job_details.metadata = {'url': '/farm-operations/ingest-data/{jobId}'}  # type: ignore
