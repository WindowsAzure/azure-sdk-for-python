# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, AsyncIterable, Callable, Dict, Generic, Optional, TypeVar
import warnings

from azure.core.async_paging import AsyncItemPaged, AsyncList
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest
from azure.mgmt.core.exceptions import ARMErrorFormat

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class BillingRoleAssignmentsOperations:
    """BillingRoleAssignmentsOperations async operations.

    You should not instantiate this class directly. Instead, you should create a Client instance that
    instantiates it for you and attaches it as an attribute.

    :ivar models: Alias to model classes used in this operation group.
    :type models: ~azure.mgmt.billing.models
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

    async def get_by_billing_account(
        self,
        billing_account_name: str,
        billing_role_assignment_name: str,
        **kwargs
    ) -> "_models.BillingRoleAssignment":
        """Gets a role assignment for the caller on a billing account. The operation is supported for
        billing accounts with agreement type Microsoft Partner Agreement or Microsoft Customer
        Agreement.

        :param billing_account_name: The ID that uniquely identifies a billing account.
        :type billing_account_name: str
        :param billing_role_assignment_name: The ID that uniquely identifies a role assignment.
        :type billing_role_assignment_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: BillingRoleAssignment, or the result of cls(response)
        :rtype: ~azure.mgmt.billing.models.BillingRoleAssignment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.BillingRoleAssignment"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-05-01"
        accept = "application/json"

        # Construct URL
        url = self.get_by_billing_account.metadata['url']  # type: ignore
        path_format_arguments = {
            'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str'),
            'billingRoleAssignmentName': self._serialize.url("billing_role_assignment_name", billing_role_assignment_name, 'str'),
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
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('BillingRoleAssignment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_by_billing_account.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingRoleAssignments/{billingRoleAssignmentName}'}  # type: ignore

    async def delete_by_billing_account(
        self,
        billing_account_name: str,
        billing_role_assignment_name: str,
        **kwargs
    ) -> "_models.BillingRoleAssignment":
        """Deletes a role assignment for the caller on a billing account. The operation is supported for
        billing accounts with agreement type Microsoft Partner Agreement or Microsoft Customer
        Agreement.

        :param billing_account_name: The ID that uniquely identifies a billing account.
        :type billing_account_name: str
        :param billing_role_assignment_name: The ID that uniquely identifies a role assignment.
        :type billing_role_assignment_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: BillingRoleAssignment, or the result of cls(response)
        :rtype: ~azure.mgmt.billing.models.BillingRoleAssignment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.BillingRoleAssignment"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-05-01"
        accept = "application/json"

        # Construct URL
        url = self.delete_by_billing_account.metadata['url']  # type: ignore
        path_format_arguments = {
            'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str'),
            'billingRoleAssignmentName': self._serialize.url("billing_role_assignment_name", billing_role_assignment_name, 'str'),
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

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('BillingRoleAssignment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    delete_by_billing_account.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingRoleAssignments/{billingRoleAssignmentName}'}  # type: ignore

    async def get_by_invoice_section(
        self,
        billing_account_name: str,
        billing_profile_name: str,
        invoice_section_name: str,
        billing_role_assignment_name: str,
        **kwargs
    ) -> "_models.BillingRoleAssignment":
        """Gets a role assignment for the caller on an invoice section. The operation is supported for
        billing accounts with agreement type Microsoft Customer Agreement.

        :param billing_account_name: The ID that uniquely identifies a billing account.
        :type billing_account_name: str
        :param billing_profile_name: The ID that uniquely identifies a billing profile.
        :type billing_profile_name: str
        :param invoice_section_name: The ID that uniquely identifies an invoice section.
        :type invoice_section_name: str
        :param billing_role_assignment_name: The ID that uniquely identifies a role assignment.
        :type billing_role_assignment_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: BillingRoleAssignment, or the result of cls(response)
        :rtype: ~azure.mgmt.billing.models.BillingRoleAssignment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.BillingRoleAssignment"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-05-01"
        accept = "application/json"

        # Construct URL
        url = self.get_by_invoice_section.metadata['url']  # type: ignore
        path_format_arguments = {
            'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str'),
            'billingProfileName': self._serialize.url("billing_profile_name", billing_profile_name, 'str'),
            'invoiceSectionName': self._serialize.url("invoice_section_name", invoice_section_name, 'str'),
            'billingRoleAssignmentName': self._serialize.url("billing_role_assignment_name", billing_role_assignment_name, 'str'),
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
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('BillingRoleAssignment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_by_invoice_section.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingProfiles/{billingProfileName}/invoiceSections/{invoiceSectionName}/billingRoleAssignments/{billingRoleAssignmentName}'}  # type: ignore

    async def delete_by_invoice_section(
        self,
        billing_account_name: str,
        billing_profile_name: str,
        invoice_section_name: str,
        billing_role_assignment_name: str,
        **kwargs
    ) -> "_models.BillingRoleAssignment":
        """Deletes a role assignment for the caller on an invoice section. The operation is supported for
        billing accounts with agreement type Microsoft Customer Agreement.

        :param billing_account_name: The ID that uniquely identifies a billing account.
        :type billing_account_name: str
        :param billing_profile_name: The ID that uniquely identifies a billing profile.
        :type billing_profile_name: str
        :param invoice_section_name: The ID that uniquely identifies an invoice section.
        :type invoice_section_name: str
        :param billing_role_assignment_name: The ID that uniquely identifies a role assignment.
        :type billing_role_assignment_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: BillingRoleAssignment, or the result of cls(response)
        :rtype: ~azure.mgmt.billing.models.BillingRoleAssignment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.BillingRoleAssignment"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-05-01"
        accept = "application/json"

        # Construct URL
        url = self.delete_by_invoice_section.metadata['url']  # type: ignore
        path_format_arguments = {
            'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str'),
            'billingProfileName': self._serialize.url("billing_profile_name", billing_profile_name, 'str'),
            'invoiceSectionName': self._serialize.url("invoice_section_name", invoice_section_name, 'str'),
            'billingRoleAssignmentName': self._serialize.url("billing_role_assignment_name", billing_role_assignment_name, 'str'),
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

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('BillingRoleAssignment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    delete_by_invoice_section.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingProfiles/{billingProfileName}/invoiceSections/{invoiceSectionName}/billingRoleAssignments/{billingRoleAssignmentName}'}  # type: ignore

    async def get_by_billing_profile(
        self,
        billing_account_name: str,
        billing_profile_name: str,
        billing_role_assignment_name: str,
        **kwargs
    ) -> "_models.BillingRoleAssignment":
        """Gets a role assignment for the caller on a billing profile. The operation is supported for
        billing accounts with agreement type Microsoft Partner Agreement or Microsoft Customer
        Agreement.

        :param billing_account_name: The ID that uniquely identifies a billing account.
        :type billing_account_name: str
        :param billing_profile_name: The ID that uniquely identifies a billing profile.
        :type billing_profile_name: str
        :param billing_role_assignment_name: The ID that uniquely identifies a role assignment.
        :type billing_role_assignment_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: BillingRoleAssignment, or the result of cls(response)
        :rtype: ~azure.mgmt.billing.models.BillingRoleAssignment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.BillingRoleAssignment"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-05-01"
        accept = "application/json"

        # Construct URL
        url = self.get_by_billing_profile.metadata['url']  # type: ignore
        path_format_arguments = {
            'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str'),
            'billingProfileName': self._serialize.url("billing_profile_name", billing_profile_name, 'str'),
            'billingRoleAssignmentName': self._serialize.url("billing_role_assignment_name", billing_role_assignment_name, 'str'),
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
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('BillingRoleAssignment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    get_by_billing_profile.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingProfiles/{billingProfileName}/billingRoleAssignments/{billingRoleAssignmentName}'}  # type: ignore

    async def delete_by_billing_profile(
        self,
        billing_account_name: str,
        billing_profile_name: str,
        billing_role_assignment_name: str,
        **kwargs
    ) -> "_models.BillingRoleAssignment":
        """Deletes a role assignment for the caller on a billing profile. The operation is supported for
        billing accounts with agreement type Microsoft Partner Agreement or Microsoft Customer
        Agreement.

        :param billing_account_name: The ID that uniquely identifies a billing account.
        :type billing_account_name: str
        :param billing_profile_name: The ID that uniquely identifies a billing profile.
        :type billing_profile_name: str
        :param billing_role_assignment_name: The ID that uniquely identifies a role assignment.
        :type billing_role_assignment_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: BillingRoleAssignment, or the result of cls(response)
        :rtype: ~azure.mgmt.billing.models.BillingRoleAssignment
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.BillingRoleAssignment"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-05-01"
        accept = "application/json"

        # Construct URL
        url = self.delete_by_billing_profile.metadata['url']  # type: ignore
        path_format_arguments = {
            'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str'),
            'billingProfileName': self._serialize.url("billing_profile_name", billing_profile_name, 'str'),
            'billingRoleAssignmentName': self._serialize.url("billing_role_assignment_name", billing_role_assignment_name, 'str'),
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

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

        deserialized = self._deserialize('BillingRoleAssignment', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    delete_by_billing_profile.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingProfiles/{billingProfileName}/billingRoleAssignments/{billingRoleAssignmentName}'}  # type: ignore

    def list_by_billing_account(
        self,
        billing_account_name: str,
        **kwargs
    ) -> AsyncIterable["_models.BillingRoleAssignmentListResult"]:
        """Lists the role assignments for the caller on a billing account. The operation is supported for
        billing accounts with agreement type Microsoft Partner Agreement or Microsoft Customer
        Agreement.

        :param billing_account_name: The ID that uniquely identifies a billing account.
        :type billing_account_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either BillingRoleAssignmentListResult or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.billing.models.BillingRoleAssignmentListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.BillingRoleAssignmentListResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-05-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_by_billing_account.metadata['url']  # type: ignore
                path_format_arguments = {
                    'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str'),
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

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('BillingRoleAssignmentListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list_by_billing_account.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingRoleAssignments'}  # type: ignore

    def list_by_invoice_section(
        self,
        billing_account_name: str,
        billing_profile_name: str,
        invoice_section_name: str,
        **kwargs
    ) -> AsyncIterable["_models.BillingRoleAssignmentListResult"]:
        """Lists the role assignments for the caller on an invoice section. The operation is supported for
        billing accounts with agreement type Microsoft Customer Agreement.

        :param billing_account_name: The ID that uniquely identifies a billing account.
        :type billing_account_name: str
        :param billing_profile_name: The ID that uniquely identifies a billing profile.
        :type billing_profile_name: str
        :param invoice_section_name: The ID that uniquely identifies an invoice section.
        :type invoice_section_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either BillingRoleAssignmentListResult or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.billing.models.BillingRoleAssignmentListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.BillingRoleAssignmentListResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-05-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_by_invoice_section.metadata['url']  # type: ignore
                path_format_arguments = {
                    'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str'),
                    'billingProfileName': self._serialize.url("billing_profile_name", billing_profile_name, 'str'),
                    'invoiceSectionName': self._serialize.url("invoice_section_name", invoice_section_name, 'str'),
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

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('BillingRoleAssignmentListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list_by_invoice_section.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingProfiles/{billingProfileName}/invoiceSections/{invoiceSectionName}/billingRoleAssignments'}  # type: ignore

    def list_by_billing_profile(
        self,
        billing_account_name: str,
        billing_profile_name: str,
        **kwargs
    ) -> AsyncIterable["_models.BillingRoleAssignmentListResult"]:
        """Lists the role assignments for the caller on a billing profile. The operation is supported for
        billing accounts with agreement type Microsoft Customer Agreement.

        :param billing_account_name: The ID that uniquely identifies a billing account.
        :type billing_account_name: str
        :param billing_profile_name: The ID that uniquely identifies a billing profile.
        :type billing_profile_name: str
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: An iterator like instance of either BillingRoleAssignmentListResult or the result of cls(response)
        :rtype: ~azure.core.async_paging.AsyncItemPaged[~azure.mgmt.billing.models.BillingRoleAssignmentListResult]
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.BillingRoleAssignmentListResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))
        api_version = "2020-05-01"
        accept = "application/json"

        def prepare_request(next_link=None):
            # Construct headers
            header_parameters = {}  # type: Dict[str, Any]
            header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

            if not next_link:
                # Construct URL
                url = self.list_by_billing_profile.metadata['url']  # type: ignore
                path_format_arguments = {
                    'billingAccountName': self._serialize.url("billing_account_name", billing_account_name, 'str'),
                    'billingProfileName': self._serialize.url("billing_profile_name", billing_profile_name, 'str'),
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

        async def extract_data(pipeline_response):
            deserialized = self._deserialize('BillingRoleAssignmentListResult', pipeline_response)
            list_of_elem = deserialized.value
            if cls:
                list_of_elem = cls(list_of_elem)
            return deserialized.next_link or None, AsyncList(list_of_elem)

        async def get_next(next_link=None):
            request = prepare_request(next_link)

            pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
            response = pipeline_response.http_response

            if response.status_code not in [200]:
                error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
                map_error(status_code=response.status_code, response=response, error_map=error_map)
                raise HttpResponseError(response=response, model=error, error_format=ARMErrorFormat)

            return pipeline_response

        return AsyncItemPaged(
            get_next, extract_data
        )
    list_by_billing_profile.metadata = {'url': '/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingProfiles/{billingProfileName}/billingRoleAssignments'}  # type: ignore
