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
from msrestazure.azure_exceptions import CloudError
from msrestazure.azure_operation import AzureOperationPoller

from .. import models


class SchedulesOperations(object):
    """SchedulesOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An objec model deserializer.
    :ivar api_version: Client API version. Constant value: "2016-05-15".
    """

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2016-05-15"

        self.config = config

    def list(
            self, resource_group_name, lab_name, expand=None, filter=None, top=None, orderby=None, custom_headers=None, raw=False, **operation_config):
        """List schedules in a given lab.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param lab_name: The name of the lab.
        :type lab_name: str
        :param expand: Specify the $expand query. Example:
         'properties($select=status)'
        :type expand: str
        :param filter: The filter to apply to the operation.
        :type filter: str
        :param top: The maximum number of resources to return from the
         operation.
        :type top: int
        :param orderby: The ordering expression for the results, using OData
         notation.
        :type orderby: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of :class:`Schedule
         <azure.mgmt.devtestlabs.models.Schedule>`
        :rtype: :class:`SchedulePaged
         <azure.mgmt.devtestlabs.models.SchedulePaged>`
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DevTestLab/labs/{labName}/schedules'
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'labName': self._serialize.url("lab_name", lab_name, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if expand is not None:
                    query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
                if orderby is not None:
                    query_parameters['$orderby'] = self._serialize.query("orderby", orderby, 'str')
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Content-Type'] = 'application/json; charset=utf-8'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.get(url, query_parameters)
            response = self._client.send(
                request, header_parameters, **operation_config)

            if response.status_code not in [200]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        deserialized = models.SchedulePaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.SchedulePaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized

    def get(
            self, resource_group_name, lab_name, name, expand=None, custom_headers=None, raw=False, **operation_config):
        """Get schedule.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param lab_name: The name of the lab.
        :type lab_name: str
        :param name: The name of the schedule.
        :type name: str
        :param expand: Specify the $expand query. Example:
         'properties($select=status)'
        :type expand: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: :class:`Schedule <azure.mgmt.devtestlabs.models.Schedule>` or
         :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>` if
         raw=true
        :rtype: :class:`Schedule <azure.mgmt.devtestlabs.models.Schedule>` or
         :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DevTestLab/labs/{labName}/schedules/{name}'
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'labName': self._serialize.url("lab_name", lab_name, 'str'),
            'name': self._serialize.url("name", name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if expand is not None:
            query_parameters['$expand'] = self._serialize.query("expand", expand, 'str')
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters)
        response = self._client.send(request, header_parameters, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Schedule', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def create_or_update(
            self, resource_group_name, lab_name, name, schedule, custom_headers=None, raw=False, **operation_config):
        """Create or replace an existing schedule.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param lab_name: The name of the lab.
        :type lab_name: str
        :param name: The name of the schedule.
        :type name: str
        :param schedule: A schedule.
        :type schedule: :class:`Schedule
         <azure.mgmt.devtestlabs.models.Schedule>`
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: :class:`Schedule <azure.mgmt.devtestlabs.models.Schedule>` or
         :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>` if
         raw=true
        :rtype: :class:`Schedule <azure.mgmt.devtestlabs.models.Schedule>` or
         :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DevTestLab/labs/{labName}/schedules/{name}'
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'labName': self._serialize.url("lab_name", lab_name, 'str'),
            'name': self._serialize.url("name", name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(schedule, 'Schedule')

        # Construct and send request
        request = self._client.put(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, **operation_config)

        if response.status_code not in [200, 201]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Schedule', response)
        if response.status_code == 201:
            deserialized = self._deserialize('Schedule', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def delete(
            self, resource_group_name, lab_name, name, custom_headers=None, raw=False, **operation_config):
        """Delete schedule.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param lab_name: The name of the lab.
        :type lab_name: str
        :param name: The name of the schedule.
        :type name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or
         :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>` if
         raw=true
        :rtype: None or
         :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DevTestLab/labs/{labName}/schedules/{name}'
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'labName': self._serialize.url("lab_name", lab_name, 'str'),
            'name': self._serialize.url("name", name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.delete(url, query_parameters)
        response = self._client.send(request, header_parameters, **operation_config)

        if response.status_code not in [200, 204]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response

    def update(
            self, resource_group_name, lab_name, name, schedule, custom_headers=None, raw=False, **operation_config):
        """Modify properties of schedules.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param lab_name: The name of the lab.
        :type lab_name: str
        :param name: The name of the schedule.
        :type name: str
        :param schedule: A schedule.
        :type schedule: :class:`ScheduleFragment
         <azure.mgmt.devtestlabs.models.ScheduleFragment>`
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: :class:`Schedule <azure.mgmt.devtestlabs.models.Schedule>` or
         :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>` if
         raw=true
        :rtype: :class:`Schedule <azure.mgmt.devtestlabs.models.Schedule>` or
         :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DevTestLab/labs/{labName}/schedules/{name}'
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'labName': self._serialize.url("lab_name", lab_name, 'str'),
            'name': self._serialize.url("name", name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(schedule, 'ScheduleFragment')

        # Construct and send request
        request = self._client.patch(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Schedule', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def execute(
            self, resource_group_name, lab_name, name, custom_headers=None, raw=False, **operation_config):
        """Execute a schedule. This operation can take a while to complete.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param lab_name: The name of the lab.
        :type lab_name: str
        :param name: The name of the schedule.
        :type name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :return:
         :class:`AzureOperationPoller<msrestazure.azure_operation.AzureOperationPoller>`
         instance that returns None or
         :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>` if
         raw=true
        :rtype:
         :class:`AzureOperationPoller<msrestazure.azure_operation.AzureOperationPoller>`
         or :class:`ClientRawResponse<msrest.pipeline.ClientRawResponse>`
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DevTestLab/labs/{labName}/schedules/{name}/execute'
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'labName': self._serialize.url("lab_name", lab_name, 'str'),
            'name': self._serialize.url("name", name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        def long_running_send():

            request = self._client.post(url, query_parameters)
            return self._client.send(request, header_parameters, **operation_config)

        def get_long_running_status(status_link, headers=None):

            request = self._client.get(status_link)
            if headers:
                request.headers.update(headers)
            return self._client.send(
                request, header_parameters, **operation_config)

        def get_long_running_output(response):

            if response.status_code not in [200, 202]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            if raw:
                client_raw_response = ClientRawResponse(None, response)
                return client_raw_response

        if raw:
            response = long_running_send()
            return get_long_running_output(response)

        long_running_operation_timeout = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        return AzureOperationPoller(
            long_running_send, get_long_running_output,
            get_long_running_status, long_running_operation_timeout)

    def list_applicable(
            self, resource_group_name, lab_name, name, custom_headers=None, raw=False, **operation_config):
        """Lists all applicable schedules.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param lab_name: The name of the lab.
        :type lab_name: str
        :param name: The name of the schedule.
        :type name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of :class:`Schedule
         <azure.mgmt.devtestlabs.models.Schedule>`
        :rtype: :class:`SchedulePaged
         <azure.mgmt.devtestlabs.models.SchedulePaged>`
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DevTestLab/labs/{labName}/schedules/{name}/listApplicable'
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
                    'labName': self._serialize.url("lab_name", lab_name, 'str'),
                    'name': self._serialize.url("name", name, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Content-Type'] = 'application/json; charset=utf-8'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.post(url, query_parameters)
            response = self._client.send(
                request, header_parameters, **operation_config)

            if response.status_code not in [200]:
                exp = CloudError(response)
                exp.request_id = response.headers.get('x-ms-request-id')
                raise exp

            return response

        # Deserialize response
        deserialized = models.SchedulePaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.SchedulePaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
