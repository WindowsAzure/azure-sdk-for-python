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
from azure.core.polling import AsyncLROPoller, AsyncNoPolling, AsyncPollingMethod
from azure.mgmt.core.exceptions import ARMErrorFormat
from azure.mgmt.core.polling.async_arm_polling import AsyncARMPolling

from ... import models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class CertificateOperations:
    """CertificateOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.batch.models
    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = models

    def __init__(self, client, config, serializer, deserializer) -> None:
        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self._config = config

    def list_by_batch_account(
        self,
        resource_group_name: str,
        account_name: str,
        maxresults: Optional[int] = None,
        select: Optional[str] = None,
        filter: Optional[str] = None,
        **kwargs
    ) -> AsyncIterable["models.ListCertificatesResult"]:
        """Lists all of the certificates in the specified account.

        :param resource_group_name: The name of the resource group that contains the Batch account.
        :type resource_group_name: str
        :param account_name: The name of the Batch account.
        :type account_name: str
        :param maxresults: The maximum number of items to return in the response.
        :type maxresults: int
        :param select: Comma separated list of properties that should be returned. e.g.
         "properties/provisioningState". Only top level properties under properties/ are valid for
         selection.
        :type select: str
        :param filter: OData filter expression. Valid properties for filtering are
         "properties/provisioningState", "properties/provisioningStateTransitionTime", "name".
        :type filter: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either ListCertificatesResult or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.batch.models.ListCertificatesResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.ListCertificatesResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-09-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_by_batch_account.metadata['url']  # type: ignore
                path_format_arguments = {
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'accountName': self._serialize.url("account_name", account_name, 'str', max_length=24, min_length=3, pattern=r'^[a-zA-Z0-9]+$'),
                    'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
                }
                url = self._client.format_url(url, **path_format_arguments)
                # Construct parameters
                query_parameters = {}  # type: Dict[str, Any]
                if maxresults is not None:
                    query_parameters['maxresults'] = self._serialize.query("maxresults", maxresults, 'int')
                if select is not None:
                    query_parameters['$select'] = self._serialize.query("select", select, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

                request = self._client.get(url, query_parameters, header_parameters)
            else:
                url = next_link
                query_parameters = {}  # type: Dict[str, Any]
                request = self._client.get(url, query_parameters, header_parameters)
            return request

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('ListCertificatesResult', pipeline_response)
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
    list_by_batch_account.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}/certificates'}  # type: ignore

    async def _create_initial(
        self,
        resource_group_name: str,
        account_name: str,
        certificate_name: str,
        parameters: "models.CertificateCreateOrUpdateParameters",
        if_match: Optional[str] = None,
        if_none_match: Optional[str] = None,
        **kwargs
    ) -> "models.Certificate":
        cls = kwargs.pop('cls', None)  # type: ClsType["models.Certificate"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-09-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self._create_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str', max_length=24, min_length=3, pattern=r'^[a-zA-Z0-9]+$'),
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str', max_length=45, min_length=5, pattern=r'^[\w]+-[\w]+$'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
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
        body_content = self._serialize.body(parameters, 'CertificateCreateOrUpdateParameters')
        body_content_kwargs['content'] = body_content
        request = self._client.put(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        response_headers = {}
        response_headers['ETag']=self._deserialize('str', response.headers.get('ETag'))
        deserialized = self._deserialize('Certificate', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    _create_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}/certificates/{certificateName}'}  # type: ignore

    async def begin_create(
        self,
        resource_group_name: str,
        account_name: str,
        certificate_name: str,
        parameters: "models.CertificateCreateOrUpdateParameters",
        if_match: Optional[str] = None,
        if_none_match: Optional[str] = None,
        **kwargs
    ) -> AsyncLROPoller["models.Certificate"]:
        """Creates a new certificate inside the specified account.

        :param resource_group_name: The name of the resource group that contains the Batch account.
        :type resource_group_name: str
        :param account_name: The name of the Batch account.
        :type account_name: str
        :param certificate_name: The identifier for the certificate. This must be made up of algorithm
         and thumbprint separated by a dash, and must match the certificate data in the request. For
         example SHA1-a3d1c5.
        :type certificate_name: str
        :param parameters: Additional parameters for certificate creation.
        :type parameters: ~azure.mgmt.batch.models.CertificateCreateOrUpdateParameters
        :param if_match: The entity state (ETag) version of the certificate to update. A value of "*"
         can be used to apply the operation only if the certificate already exists. If omitted, this
         operation will always be applied.
        :type if_match: str
        :param if_none_match: Set to '*' to allow a new certificate to be created, but to prevent
         updating an existing certificate. Other values will be ignored.
        :type if_none_match: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either Certificate or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[~azure.mgmt.batch.models.Certificate]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType["models.Certificate"]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = await self._create_initial(
                resource_group_name=resource_group_name,
                account_name=account_name,
                certificate_name=certificate_name,
                parameters=parameters,
                if_match=if_match,
                if_none_match=if_none_match,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            response_headers = {}
            response = pipeline_response.http_response
            response_headers['ETag']=self._deserialize('str', response.headers.get('ETag'))
            deserialized = self._deserialize('Certificate', pipeline_response)

            if cls:
                return cls(pipeline_response, deserialized, response_headers)
            return deserialized

        if polling is True: polling_method = AsyncARMPolling(lro_delay,  **kwargs)
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
    begin_create.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}/certificates/{certificateName}'}  # type: ignore

    async def update(
        self,
        resource_group_name: str,
        account_name: str,
        certificate_name: str,
        parameters: "models.CertificateCreateOrUpdateParameters",
        if_match: Optional[str] = None,
        **kwargs
    ) -> "models.Certificate":
        """Updates the properties of an existing certificate.

        :param resource_group_name: The name of the resource group that contains the Batch account.
        :type resource_group_name: str
        :param account_name: The name of the Batch account.
        :type account_name: str
        :param certificate_name: The identifier for the certificate. This must be made up of algorithm
         and thumbprint separated by a dash, and must match the certificate data in the request. For
         example SHA1-a3d1c5.
        :type certificate_name: str
        :param parameters: Certificate entity to update.
        :type parameters: ~azure.mgmt.batch.models.CertificateCreateOrUpdateParameters
        :param if_match: The entity state (ETag) version of the certificate to update. This value can
         be omitted or set to "*" to apply the operation unconditionally.
        :type if_match: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Certificate, or the result of cls(response)
        :rtype: ~azure.mgmt.batch.models.Certificate
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.Certificate"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-09-01"
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json"

        # Construct URL
        url = self.update.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str', max_length=24, min_length=3, pattern=r'^[a-zA-Z0-9]+$'),
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str', max_length=45, min_length=5, pattern=r'^[\w]+-[\w]+$'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
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
        body_content = self._serialize.body(parameters, 'CertificateCreateOrUpdateParameters')
        body_content_kwargs['content'] = body_content
        request = self._client.patch(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        response_headers = {}
        response_headers['ETag']=self._deserialize('str', response.headers.get('ETag'))
        deserialized = self._deserialize('Certificate', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}/certificates/{certificateName}'}  # type: ignore

    async def _delete_initial(
        self,
        resource_group_name: str,
        account_name: str,
        certificate_name: str,
        **kwargs
    ) -> None:
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-09-01"
        accept = "application/json"

        # Construct URL
        url = self._delete_initial.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str', max_length=24, min_length=3, pattern=r'^[a-zA-Z0-9]+$'),
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str', max_length=45, min_length=5, pattern=r'^[\w]+-[\w]+$'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.delete(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200, 202, 204]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        response_headers = {}
        if response.status_code == 202:
            response_headers['Location']=self._deserialize('str', response.headers.get('Location'))
            response_headers['Retry-After']=self._deserialize('int', response.headers.get('Retry-After'))

        if cls:
            return cls(pipeline_response, None, response_headers)

    _delete_initial.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}/certificates/{certificateName}'}  # type: ignore

    async def begin_delete(
        self,
        resource_group_name: str,
        account_name: str,
        certificate_name: str,
        **kwargs
    ) -> AsyncLROPoller[None]:
        """Deletes the specified certificate.

        :param resource_group_name: The name of the resource group that contains the Batch account.
        :type resource_group_name: str
        :param account_name: The name of the Batch account.
        :type account_name: str
        :param certificate_name: The identifier for the certificate. This must be made up of algorithm
         and thumbprint separated by a dash, and must match the certificate data in the request. For
         example SHA1-a3d1c5.
        :type certificate_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :keyword str continuation_token: A continuation token to restart a poller from a saved state.
        :keyword polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :paramtype polling: bool or ~azure.core.polling.AsyncPollingMethod
        :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
        :return: An instance of AsyncLROPoller that returns either None or the result of cls(response)
        :rtype: ~azure.core.polling.AsyncLROPoller[None]
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        polling = kwargs.pop('polling', True)  # type: Union[bool, AsyncPollingMethod]
        cls = kwargs.pop('cls', None)  # type: ClsType[None]
        lro_delay = kwargs.pop(
            'polling_interval',
            self._config.polling_interval
        )
        cont_token = kwargs.pop('continuation_token', None)  # type: Optional[str]
        if cont_token is None:
            raw_result = await self._delete_initial(
                resource_group_name=resource_group_name,
                account_name=account_name,
                certificate_name=certificate_name,
                cls=lambda x,y,z: x,
                **kwargs
            )

        kwargs.pop('error_map', None)
        kwargs.pop('content_type', None)

        def get_long_running_output(pipeline_response):
            if cls:
                return cls(pipeline_response, None, {})

        if polling is True: polling_method = AsyncARMPolling(lro_delay,  **kwargs)
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
    begin_delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}/certificates/{certificateName}'}  # type: ignore

    async def get(
        self,
        resource_group_name: str,
        account_name: str,
        certificate_name: str,
        **kwargs
    ) -> "models.Certificate":
        """Gets information about the specified certificate.

        :param resource_group_name: The name of the resource group that contains the Batch account.
        :type resource_group_name: str
        :param account_name: The name of the Batch account.
        :type account_name: str
        :param certificate_name: The identifier for the certificate. This must be made up of algorithm
         and thumbprint separated by a dash, and must match the certificate data in the request. For
         example SHA1-a3d1c5.
        :type certificate_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Certificate, or the result of cls(response)
        :rtype: ~azure.mgmt.batch.models.Certificate
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.Certificate"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-09-01"
        accept = "application/json"

        # Construct URL
        url = self.get.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str', max_length=24, min_length=3, pattern=r'^[a-zA-Z0-9]+$'),
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str', max_length=45, min_length=5, pattern=r'^[\w]+-[\w]+$'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
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

        response_headers = {}
        response_headers['ETag']=self._deserialize('str', response.headers.get('ETag'))
        deserialized = self._deserialize('Certificate', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}/certificates/{certificateName}'}  # type: ignore

    async def cancel_deletion(
        self,
        resource_group_name: str,
        account_name: str,
        certificate_name: str,
        **kwargs
    ) -> "models.Certificate":
        """Cancels a failed deletion of a certificate from the specified account.

        If you try to delete a certificate that is being used by a pool or compute node, the status of
        the certificate changes to deleteFailed. If you decide that you want to continue using the
        certificate, you can use this operation to set the status of the certificate back to active. If
        you intend to delete the certificate, you do not need to run this operation after the deletion
        failed. You must make sure that the certificate is not being used by any resources, and then
        you can try again to delete the certificate.

        :param resource_group_name: The name of the resource group that contains the Batch account.
        :type resource_group_name: str
        :param account_name: The name of the Batch account.
        :type account_name: str
        :param certificate_name: The identifier for the certificate. This must be made up of algorithm
         and thumbprint separated by a dash, and must match the certificate data in the request. For
         example SHA1-a3d1c5.
        :type certificate_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: Certificate, or the result of cls(response)
        :rtype: ~azure.mgmt.batch.models.Certificate
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["models.Certificate"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-09-01"
        accept = "application/json"

        # Construct URL
        url = self.cancel_deletion.metadata['url']  # type: ignore
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str', max_length=24, min_length=3, pattern=r'^[a-zA-Z0-9]+$'),
            'certificateName': self._serialize.url("certificate_name", certificate_name, 'str', max_length=45, min_length=5, pattern=r'^[\w]+-[\w]+$'),
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        request = self._client.post(url, query_parameters, header_parameters)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        response_headers = {}
        response_headers['ETag']=self._deserialize('str', response.headers.get('ETag'))
        deserialized = self._deserialize('Certificate', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, response_headers)

        return deserialized
    cancel_deletion.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}/certificates/{certificateName}/cancelDelete'}  # type: ignore
