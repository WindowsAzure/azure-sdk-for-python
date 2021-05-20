# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import datetime
from typing import TYPE_CHECKING
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.paging import ItemPaged
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import HttpRequest, HttpResponse

from .. import models as _models

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Callable, Dict, Generic, IO, Iterable, List, Optional, TypeVar, Union

    T = TypeVar('T')
    ClsType = Optional[Callable[[PipelineResponse[HttpRequest, HttpResponse], T, Dict[str, Any]], Any]]

class AttachmentsOperations(object):
    """AttachmentsOperations operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.agrifood.farming.models
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

    def list_by_farmer_id(
        self,
        farmer_id,  # type: str
        resource_ids=None,  # type: Optional[List[str]]
        resource_types=None,  # type: Optional[List[str]]
        ids=None,  # type: Optional[List[str]]
        names=None,  # type: Optional[List[str]]
        property_filters=None,  # type: Optional[List[str]]
        statuses=None,  # type: Optional[List[str]]
        min_created_date_time=None,  # type: Optional[datetime.datetime]
        max_created_date_time=None,  # type: Optional[datetime.datetime]
        min_last_modified_date_time=None,  # type: Optional[datetime.datetime]
        max_last_modified_date_time=None,  # type: Optional[datetime.datetime]
        max_page_size=50,  # type: Optional[int]
        skip_token=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> Iterable["_models.AttachmentListResponse"]
        """Returns a paginated list of attachment resources under a particular farmer.

        :param farmer_id: ID of the associated farmer.
        :type farmer_id: str
        :param resource_ids: Resource Ids of the resource.
        :type resource_ids: list[str]
        :param resource_types: Resource Types of the resource.
        :type resource_types: list[str]
        :param ids: Ids of the resource.
        :type ids: list[str]
        :param names: Names of the resource.
        :type names: list[str]
        :param property_filters: Filters on key-value pairs within the Properties object.
         eg. "{testKey} eq {testValue}".
        :type property_filters: list[str]
        :param statuses: Statuses of the resource.
        :type statuses: list[str]
        :param min_created_date_time: Minimum creation date of resource (inclusive).
        :type min_created_date_time: ~datetime.datetime
        :param max_created_date_time: Maximum creation date of resource (inclusive).
        :type max_created_date_time: ~datetime.datetime
        :param min_last_modified_date_time: Minimum last modified date of resource (inclusive).
        :type min_last_modified_date_time: ~datetime.datetime
        :param max_last_modified_date_time: Maximum last modified date of resource (inclusive).
        :type max_last_modified_date_time: ~datetime.datetime
        :param max_page_size: Maximum number of items needed (inclusive).
         Minimum = 10, Maximum = 1000, Default value = 50.
        :type max_page_size: int
        :param skip_token: Skip token for getting next set of results.
        :type skip_token: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either AttachmentListResponse or the result of cls(response)
        :rtype: ~azure.core.paging.ItemPaged[~azure.agrifood.farming.models.AttachmentListResponse]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.AttachmentListResponse"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-03-31-preview"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_by_farmer_id.metadata['url']  # type: ignore
                path_format_arguments = {
                    'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
                    'farmerId': self._serialize.url("farmer_id", farmer_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if resource_ids is not None:
                    query_parameters['resourceIds'] = [self._serialize.query("resource_ids", q, 'str') if q is not None else '' for q in resource_ids]
                if resource_types is not None:
                    query_parameters['resourceTypes'] = [self._serialize.query("resource_types", q, 'str') if q is not None else '' for q in resource_types]
                if ids is not None:
                    query_parameters['ids'] = [self._serialize.query("ids", q, 'str') if q is not None else '' for q in ids]
                if names is not None:
                    query_parameters['names'] = [self._serialize.query("names", q, 'str') if q is not None else '' for q in names]
                if property_filters is not None:
                    query_parameters['propertyFilters'] = [self._serialize.query("property_filters", q, 'str') if q is not None else '' for q in property_filters]
                if statuses is not None:
                    query_parameters['statuses'] = [self._serialize.query("statuses", q, 'str') if q is not None else '' for q in statuses]
                if min_created_date_time is not None:
                    query_parameters['minCreatedDateTime'] = self._serialize.query("min_created_date_time", min_created_date_time, 'iso-8601')
                if max_created_date_time is not None:
                    query_parameters['maxCreatedDateTime'] = self._serialize.query("max_created_date_time", max_created_date_time, 'iso-8601')
                if min_last_modified_date_time is not None:
                    query_parameters['minLastModifiedDateTime'] = self._serialize.query("min_last_modified_date_time", min_last_modified_date_time, 'iso-8601')
                if max_last_modified_date_time is not None:
                    query_parameters['maxLastModifiedDateTime'] = self._serialize.query("max_last_modified_date_time", max_last_modified_date_time, 'iso-8601')
                if max_page_size is not None:
                    query_parameters['$maxPageSize'] = self._serialize.query("max_page_size", max_page_size, 'int', maximum=1000, minimum=10)
                if skip_token is not None:
                    query_parameters['$skipToken'] = self._serialize.query("skip_token", skip_token, 'str')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                path_format_arguments = {
                    'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
                    'farmerId': self._serialize.url("farmer_id", farmer_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        def extract_data(pipeline_response):
            deserialized = self._deserialize('AttachmentListResponse', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, iter(list_of_elem)

        def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error)

            return pipeline_response

        return ItemPaged(
            get_next, extract_data
        )
    list_by_farmer_id.metadata = {'url': '/farmers/{farmerId}/attachments'}  # type: ignore

    def get(
        self,
        farmer_id,  # type: str
        attachment_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.Attachment"
        """Gets a specified attachment resource under a particular farmer.

        :param farmer_id: ID of the associated farmer.
        :type farmer_id: str
        :param attachment_id: ID of the attachment.
        :type attachment_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Attachment, or the result of cls(response)
        :rtype: ~azure.agrifood.farming.models.Attachment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Attachment"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-03-31-preview"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'farmerId': self._serialize.url("farmer_id", farmer_id, 'str'),
            'attachmentId': self._serialize.url("attachment_id", attachment_id, 'str'),
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
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('Attachment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/farmers/{farmerId}/attachments/{attachmentId}'}  # type: ignore

    def create_or_update(
        self,
        farmer_id,  # type: str
        attachment_id,  # type: str
        file=None,  # type: Optional[IO]
        farmer_id1=None,  # type: Optional[str]
        resource_id=None,  # type: Optional[str]
        resource_type=None,  # type: Optional[str]
        original_file_name=None,  # type: Optional[str]
        id=None,  # type: Optional[str]
        status=None,  # type: Optional[str]
        created_date_time=None,  # type: Optional[str]
        modified_date_time=None,  # type: Optional[str]
        name=None,  # type: Optional[str]
        description=None,  # type: Optional[str]
        e_tag=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> "_models.Attachment"
        """Creates or updates an attachment resource under a particular farmer.

        :param farmer_id: ID of the associated farmer resource.
        :type farmer_id: str
        :param attachment_id: ID of the attachment resource.
        :type attachment_id: str
        :param file: File to be uploaded.
        :type file: IO
        :param farmer_id1: Farmer id for this attachment.
        :type farmer_id1: str
        :param resource_id: Associated Resource id for this attachment.
        :type resource_id: str
        :param resource_type: Associated Resource type for this attachment
         i.e. Farmer, Farm, Field, SeasonalField, Boundary, FarmOperationApplicationData, HarvestData,
         TillageData, PlantingData.
        :type resource_type: str
        :param original_file_name: Original File Name for this attachment.
        :type original_file_name: str
        :param id: Unique id.
        :type id: str
        :param status: Status of the resource.
        :type status: str
        :param created_date_time: Date when resource was created.
        :type created_date_time: str
        :param modified_date_time: Date when resource was last modified.
        :type modified_date_time: str
        :param name: Name to identify resource.
        :type name: str
        :param description: Textual description of resource.
        :type description: str
        :param e_tag: The ETag value to implement optimistic concurrency.
        :type e_tag: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Attachment, or the result of cls(response)
        :rtype: ~azure.agrifood.farming.models.Attachment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.Attachment"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-03-31-preview"
        content_type = kwargs.pop("content_type", "multipart/form-data")
        accept = "application/json"

        # Construct URL
        url = self.create_or_update.metadata['url']  # type: ignore
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'farmerId': self._serialize.url("farmer_id", farmer_id, 'str'),
            'attachmentId': self._serialize.url("attachment_id", attachment_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        # Construct form data
        _form_content = {
            'file': file,
            'FarmerId': farmer_id1,
            'ResourceId': resource_id,
            'ResourceType': resource_type,
            'OriginalFileName': original_file_name,
            'Id': id,
            'Status': status,
            'CreatedDateTime': created_date_time,
            'ModifiedDateTime': modified_date_time,
            'Name': name,
            'Description': description,
            'ETag': e_tag,
        }
        request = self._client.patch(url, query_parameters, header_parameters, form_content=_form_content)
        pipeline_response = self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        if response.status_code == 200:
            deserialized = self._deserialize('Attachment', pipeline_response)

        if response.status_code == 201:
            deserialized = self._deserialize('Attachment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create_or_update.metadata = {'url': '/farmers/{farmerId}/attachments/{attachmentId}'}  # type: ignore

    def delete(
        self,
        farmer_id,  # type: str
        attachment_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        """Deletes a specified attachment resource under a particular farmer.

        :param farmer_id: ID of the farmer.
        :type farmer_id: str
        :param attachment_id: ID of the attachment.
        :type attachment_id: str
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
        api_version = "2021-03-31-preview"
        accept = "application/json"

        # Construct URL
        url = self.delete.metadata['url']  # type: ignore
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'farmerId': self._serialize.url("farmer_id", farmer_id, 'str'),
            'attachmentId': self._serialize.url("attachment_id", attachment_id, 'str'),
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

        if response.status_code not in [204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        if cls:
            return cls(pipeline_response, None, {})

    delete.metadata = {'url': '/farmers/{farmerId}/attachments/{attachmentId}'}  # type: ignore

    def download(
        self,
        farmer_id,  # type: str
        attachment_id,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> IO
        """Downloads and returns attachment as response for the given input filePath.

        :param farmer_id: ID of the associated farmer.
        :type farmer_id: str
        :param attachment_id: ID of attachment to be downloaded.
        :type attachment_id: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: IO, or the result of cls(response)
        :rtype: IO
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType[IO]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2021-03-31-preview"
        accept = "application/octet-stream, application/json"

        # Construct URL
        url = self.download.metadata['url']  # type: ignore
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
            'farmerId': self._serialize.url("farmer_id", farmer_id, 'str'),
            'attachmentId': self._serialize.url("attachment_id", attachment_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = self._client._pipeline.run(request, stream=True, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = response.stream_download(self._client._pipeline)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    download.metadata = {'url': '/farmers/{farmerId}/attachments/{attachmentId}/file'}  # type: ignore
