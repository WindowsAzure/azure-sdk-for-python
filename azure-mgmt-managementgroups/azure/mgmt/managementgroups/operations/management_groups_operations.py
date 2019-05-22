# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

import uuid
from msrest.pipeline import ClientRawResponse
from msrest.polling import LROPoller, NoPolling
from msrestazure.polling.arm_polling import ARMPolling

from .. import models


class ManagementGroupsOperations(object):
    """ManagementGroupsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of the API to be used with the client request. The current version is 2018-01-01-preview. Constant value: "2018-03-01-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-03-01-preview"

        self.config = config

    def list(
            self, cache_control="no-cache", skiptoken=None, custom_headers=None, raw=False, **operation_config):
        """List management groups for the authenticated user.

        :param cache_control: Indicates that the request shouldn't utilize any
         caches.
        :type cache_control: str
        :param skiptoken: Page continuation token is only used if a previous
         operation returned a partial result. If a previous response contains a
         nextLink element, the value of the nextLink element will include a
         token parameter that specifies a starting point to use for subsequent
         calls.
        :type skiptoken: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of ManagementGroupInfo
        :rtype:
         ~azure.mgmt.managementgroups.models.ManagementGroupInfoPaged[~azure.mgmt.managementgroups.models.ManagementGroupInfo]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.managementgroups.models.ErrorResponseException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
                if skiptoken is not None:
                    query_parameters['$skiptoken'] = self._serialize.query("skiptoken", skiptoken, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Accept'] = 'application/json'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if cache_control is not None:
                header_parameters['Cache-Control'] = self._serialize.header("cache_control", cache_control, 'str')
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.ManagementGroupInfoPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.ManagementGroupInfoPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/providers/Microsoft.Management/managementGroups'}

    def get(
            self, group_id, expand=None, recurse=None, filter=None, cache_control="no-cache", custom_headers=None, raw=False, **operation_config):
        """Get the details of the management group.

        :param group_id: Management Group ID.
        :type group_id: str
        :param expand: The $expand=children query string parameter allows
         clients to request inclusion of children in the response payload.
         Possible values include: 'children'
        :type expand: str
        :param recurse: The $recurse=true query string parameter allows
         clients to request inclusion of entire hierarchy in the response
         payload. Note that  $expand=children must be passed up if $recurse is
         set to true.
        :type recurse: bool
        :param filter: A filter which allows the exclusion of subscriptions
         from results (i.e. '$filter=children.childType ne Subscription')
        :type filter: str
        :param cache_control: Indicates that the request shouldn't utilize any
         caches.
        :type cache_control: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ManagementGroup or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.managementgroups.models.ManagementGroup or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.managementgroups.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'groupId': self._serialize.url("group_id", group_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')
        if expand is not None:
            query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')
        if recurse is not None:
            query_parameters['$recurse'] = self._serialize.query("recurse", recurse, 'bool')
        if filter is not None:
            query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if cache_control is not None:
            header_parameters['Cache-Control'] = self._serialize.header("cache_control", cache_control, 'str')
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ManagementGroup', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/providers/Microsoft.Management/managementGroups/{groupId}'}


    def _create_or_update_initial(
            self, group_id, create_management_group_request, cache_control="no-cache", custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.create_or_update.metadata['url']
        path_format_arguments = {
            'groupId': self._serialize.url("group_id", group_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if cache_control is not None:
            header_parameters['Cache-Control'] = self._serialize.header("cache_control", cache_control, 'str')
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(create_management_group_request, 'CreateManagementGroupRequest')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 202]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ManagementGroup', response)
        if response.status_code == 202:
            deserialized = self._deserialize('OperationResults', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def create_or_update(
            self, group_id, create_management_group_request, cache_control="no-cache", custom_headers=None, raw=False, polling=True, **operation_config):
        """Create or update a management group. If a management group is already
        created and a subsequent create request is issued with different
        properties, the management group properties will be updated.

        :param group_id: Management Group ID.
        :type group_id: str
        :param create_management_group_request: Management group creation
         parameters.
        :type create_management_group_request:
         ~azure.mgmt.managementgroups.models.CreateManagementGroupRequest
        :param cache_control: Indicates that the request shouldn't utilize any
         caches.
        :type cache_control: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns object or
         ClientRawResponse<object> if raw==True
        :rtype: ~msrestazure.azure_operation.AzureOperationPoller[object] or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[object]]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.managementgroups.models.ErrorResponseException>`
        """
        raw_result = self._create_or_update_initial(
            group_id=group_id,
            create_management_group_request=create_management_group_request,
            cache_control=cache_control,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('object', response)

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                return client_raw_response

            return deserialized

        lro_delay = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        if polling is True: polling_method = ARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    create_or_update.metadata = {'url': '/providers/Microsoft.Management/managementGroups/{groupId}'}

    def update(
            self, group_id, patch_group_request, cache_control="no-cache", custom_headers=None, raw=False, **operation_config):
        """Update a management group.

        :param group_id: Management Group ID.
        :type group_id: str
        :param patch_group_request: Management group patch parameters.
        :type patch_group_request:
         ~azure.mgmt.managementgroups.models.PatchManagementGroupRequest
        :param cache_control: Indicates that the request shouldn't utilize any
         caches.
        :type cache_control: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ManagementGroup or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.managementgroups.models.ManagementGroup or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.managementgroups.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.update.metadata['url']
        path_format_arguments = {
            'groupId': self._serialize.url("group_id", group_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if cache_control is not None:
            header_parameters['Cache-Control'] = self._serialize.header("cache_control", cache_control, 'str')
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(patch_group_request, 'PatchManagementGroupRequest')

        # Construct and send request
        request = self._client.patch(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ManagementGroup', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    update.metadata = {'url': '/providers/Microsoft.Management/managementGroups/{groupId}'}


    def _delete_initial(
            self, group_id, cache_control="no-cache", custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'groupId': self._serialize.url("group_id", group_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if cache_control is not None:
            header_parameters['Cache-Control'] = self._serialize.header("cache_control", cache_control, 'str')
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [202, 204]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 202:
            deserialized = self._deserialize('OperationResults', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def delete(
            self, group_id, cache_control="no-cache", custom_headers=None, raw=False, polling=True, **operation_config):
        """Delete management group. If a management group contains child
        resources, the request will fail.

        :param group_id: Management Group ID.
        :type group_id: str
        :param cache_control: Indicates that the request shouldn't utilize any
         caches.
        :type cache_control: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns OperationResults or
         ClientRawResponse<OperationResults> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.managementgroups.models.OperationResults]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.managementgroups.models.OperationResults]]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.managementgroups.models.ErrorResponseException>`
        """
        raw_result = self._delete_initial(
            group_id=group_id,
            cache_control=cache_control,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('OperationResults', response)

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                return client_raw_response

            return deserialized

        lro_delay = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        if polling is True: polling_method = ARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    delete.metadata = {'url': '/providers/Microsoft.Management/managementGroups/{groupId}'}
