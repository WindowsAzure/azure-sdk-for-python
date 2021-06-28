# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, AsyncIterable, Callable, Dict, Generic, Optional, TypeVar, Union
import warnings

from azure.core.async_paging import AsyncItemPaged, AsyncList
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.mgmt.core.exceptions import ARMErrorFormat

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class RecordSetsOperations:
    """RecordSetsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.dns.v2016_04_01.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = _models

    def __init__(self, client, config, serializer, deserializer) -> None:
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    async def update(
        self,
        resource_group_name: str,
        zone_name: str,
        relative_record_set_name: str,
        record_type: Union[str, "_models.RecordType"],
        parameters: "_models.RecordSet",
        if_match: Optional[str] = None,
        **kwargs: Any
    ) -> "_models.RecordSet":
        """Updates a record set within a DNS zone.

        :param resource_group_name: The name of the resource group. The name is case insensitive.
        :type resource_group_name: str
        :param zone_name: The name of the DNS zone (without a terminating dot).
        :type zone_name: str
        :param relative_record_set_name: The name of the record set, relative to the name of the zone.
        :type relative_record_set_name: str
        :param record_type: The type of DNS record in this record set.
        :type record_type: str or ~azure.mgmt.dns.v2016_04_01.models.RecordType
        :param parameters: Parameters supplied to the Update operation.
        :type parameters: ~azure.mgmt.dns.v2016_04_01.models.RecordSet
        :param if_match: The etag of the record set. Omit this value to always overwrite the current
         record set. Specify the last-seen etag value to prevent accidentally overwriting concurrent
         changes.
        :type if_match: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: RecordSet, or the result of cls(response)
        :rtype: ~azure.mgmt.dns.v2016_04_01.models.RecordSet
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.RecordSet"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2016-04-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.update.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1),
            'zoneName': self._serialize.url("zone_name", zone_name, 'str'),
            'relativeRecordSetName': self._serialize.url("relative_record_set_name", relative_record_set_name, 'str', skip_quote=True),
            'recordType': self._serialize.url("record_type", record_type, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(parameters, 'RecordSet')
        body_content_kwargs['content'] = body_content
        request = self._client.patch(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('RecordSet', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnsZones/{zoneName}/{recordType}/{relativeRecordSetName}'}  # type: ignore

    async def create_or_update(
        self,
        resource_group_name: str,
        zone_name: str,
        relative_record_set_name: str,
        record_type: Union[str, "_models.RecordType"],
        parameters: "_models.RecordSet",
        if_match: Optional[str] = None,
        if_none_match: Optional[str] = None,
        **kwargs: Any
    ) -> "_models.RecordSet":
        """Creates or updates a record set within a DNS zone.

        :param resource_group_name: The name of the resource group. The name is case insensitive.
        :type resource_group_name: str
        :param zone_name: The name of the DNS zone (without a terminating dot).
        :type zone_name: str
        :param relative_record_set_name: The name of the record set, relative to the name of the zone.
        :type relative_record_set_name: str
        :param record_type: The type of DNS record in this record set. Record sets of type SOA can be
         updated but not created (they are created when the DNS zone is created).
        :type record_type: str or ~azure.mgmt.dns.v2016_04_01.models.RecordType
        :param parameters: Parameters supplied to the CreateOrUpdate operation.
        :type parameters: ~azure.mgmt.dns.v2016_04_01.models.RecordSet
        :param if_match: The etag of the record set. Omit this value to always overwrite the current
         record set. Specify the last-seen etag value to prevent accidentally overwriting any concurrent
         changes.
        :type if_match: str
        :param if_none_match: Set to '*' to allow a new record set to be created, but to prevent
         updating an existing record set. Other values will be ignored.
        :type if_none_match: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: RecordSet, or the result of cls(response)
        :rtype: ~azure.mgmt.dns.v2016_04_01.models.RecordSet
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.RecordSet"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2016-04-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.create_or_update.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1),
            'zoneName': self._serialize.url("zone_name", zone_name, 'str'),
            'relativeRecordSetName': self._serialize.url("relative_record_set_name", relative_record_set_name, 'str', skip_quote=True),
            'recordType': self._serialize.url("record_type", record_type, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        if if_none_match is not None:
            header_parameters['If-None-Match'] = self._serialize.header("if_none_match", if_none_match, 'str')
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(parameters, 'RecordSet')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 201]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if response.status_code == 200:
            deserialized = self._deserialize('RecordSet', pipeline_response)

        if response.status_code == 201:
            deserialized = self._deserialize('RecordSet', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnsZones/{zoneName}/{recordType}/{relativeRecordSetName}'}  # type: ignore

    async def delete(
        self,
        resource_group_name: str,
        zone_name: str,
        relative_record_set_name: str,
        record_type: Union[str, "_models.RecordType"],
        if_match: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """Deletes a record set from a DNS zone. This operation cannot be undone.

        :param resource_group_name: The name of the resource group. The name is case insensitive.
        :type resource_group_name: str
        :param zone_name: The name of the DNS zone (without a terminating dot).
        :type zone_name: str
        :param relative_record_set_name: The name of the record set, relative to the name of the zone.
        :type relative_record_set_name: str
        :param record_type: The type of DNS record in this record set. Record sets of type SOA cannot
         be deleted (they are deleted when the DNS zone is deleted).
        :type record_type: str or ~azure.mgmt.dns.v2016_04_01.models.RecordType
        :param if_match: The etag of the record set. Omit this value to always delete the current
         record set. Specify the last-seen etag value to prevent accidentally deleting any concurrent
         changes.
        :type if_match: str
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
        api_version = "2016-04-01"
        accept = "application/json"

        # Construct URL
        url = self.delete.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1),
            'zoneName': self._serialize.url("zone_name", zone_name, 'str'),
            'relativeRecordSetName': self._serialize.url("relative_record_set_name", relative_record_set_name, 'str', skip_quote=True),
            'recordType': self._serialize.url("record_type", record_type, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        if if_match is not None:
            header_parameters['If-Match'] = self._serialize.header("if_match", if_match, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        if cls:
            return cls(pipeline_response, None, {})

    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnsZones/{zoneName}/{recordType}/{relativeRecordSetName}'}  # type: ignore

    async def get(
        self,
        resource_group_name: str,
        zone_name: str,
        relative_record_set_name: str,
        record_type: Union[str, "_models.RecordType"],
        **kwargs: Any
    ) -> "_models.RecordSet":
        """Gets a record set.

        :param resource_group_name: The name of the resource group. The name is case insensitive.
        :type resource_group_name: str
        :param zone_name: The name of the DNS zone (without a terminating dot).
        :type zone_name: str
        :param relative_record_set_name: The name of the record set, relative to the name of the zone.
        :type relative_record_set_name: str
        :param record_type: The type of DNS record in this record set.
        :type record_type: str or ~azure.mgmt.dns.v2016_04_01.models.RecordType
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: RecordSet, or the result of cls(response)
        :rtype: ~azure.mgmt.dns.v2016_04_01.models.RecordSet
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.RecordSet"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2016-04-01"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1),
            'zoneName': self._serialize.url("zone_name", zone_name, 'str'),
            'relativeRecordSetName': self._serialize.url("relative_record_set_name", relative_record_set_name, 'str', skip_quote=True),
            'recordType': self._serialize.url("record_type", record_type, 'str'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.get(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize('RecordSet', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnsZones/{zoneName}/{recordType}/{relativeRecordSetName}'}  # type: ignore

    def list_by_type(
        self,
        resource_group_name: str,
        zone_name: str,
        record_type: Union[str, "_models.RecordType"],
        top: Optional[int] = None,
        recordsetnamesuffix: Optional[str] = None,
        **kwargs: Any
    ) -> AsyncIterable["_models.RecordSetListResult"]:
        """Lists the record sets of a specified type in a DNS zone.

        :param resource_group_name: The name of the resource group. The name is case insensitive.
        :type resource_group_name: str
        :param zone_name: The name of the DNS zone (without a terminating dot).
        :type zone_name: str
        :param record_type: The type of record sets to enumerate.
        :type record_type: str or ~azure.mgmt.dns.v2016_04_01.models.RecordType
        :param top: The maximum number of record sets to return. If not specified, returns up to 100
         record sets.
        :type top: int
        :param recordsetnamesuffix: The suffix label of the record set name that has to be used to
         filter the record set enumerations. If this parameter is specified, Enumeration will return
         only records that end with .:code:`<recordSetNameSuffix>`.
        :type recordsetnamesuffix: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either RecordSetListResult or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.dns.v2016_04_01.models.RecordSetListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.RecordSetListResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2016-04-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_by_type.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1),
                    'zoneName': self._serialize.url("zone_name", zone_name, 'str'),
                    'recordType': self._serialize.url("record_type", record_type, 'str'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
                if recordsetnamesuffix is not None:
                    query_parameters['$recordsetnamesuffix'] = self._serialize.query("recordsetnamesuffix", recordsetnamesuffix, 'str')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('RecordSetListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list_by_type.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnsZones/{zoneName}/{recordType}'}  # type: ignore

    def list_by_dns_zone(
        self,
        resource_group_name: str,
        zone_name: str,
        top: Optional[int] = None,
        recordsetnamesuffix: Optional[str] = None,
        **kwargs: Any
    ) -> AsyncIterable["_models.RecordSetListResult"]:
        """Lists all record sets in a DNS zone.

        :param resource_group_name: The name of the resource group. The name is case insensitive.
        :type resource_group_name: str
        :param zone_name: The name of the DNS zone (without a terminating dot).
        :type zone_name: str
        :param top: The maximum number of record sets to return. If not specified, returns up to 100
         record sets.
        :type top: int
        :param recordsetnamesuffix: The suffix label of the record set name that has to be used to
         filter the record set enumerations. If this parameter is specified, Enumeration will return
         only records that end with .:code:`<recordSetNameSuffix>`.
        :type recordsetnamesuffix: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either RecordSetListResult or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.dns.v2016_04_01.models.RecordSetListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.RecordSetListResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2016-04-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_by_dns_zone.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str', max_length=90, min_length=1),
                    'zoneName': self._serialize.url("zone_name", zone_name, 'str'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str', min_length=1),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
                if recordsetnamesuffix is not None:
                    query_parameters['$recordsetnamesuffix'] = self._serialize.query("recordsetnamesuffix", recordsetnamesuffix, 'str')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('RecordSetListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list_by_dns_zone.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/dnsZones/{zoneName}/recordsets'}  # type: ignore
