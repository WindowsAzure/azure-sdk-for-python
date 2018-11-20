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


class SnapshotsOperations(object):
    """SnapshotsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Version of the API to be used with the client request. Constant value: "2017-08-15".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2017-08-15"

        self.config = config

    def list(
            self, resource_group, account_name, pool_name, volume_name, custom_headers=None, raw=False, **operation_config):
        """List snapshots.

        :param resource_group: The name of the resource group.
        :type resource_group: str
        :param account_name: The name of the NetApp account
        :type account_name: str
        :param pool_name: The name of the capacity pool
        :type pool_name: str
        :param volume_name: The name of the volume
        :type volume_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of Snapshot
        :rtype:
         ~azure.mgmt.netapp.models.SnapshotPaged[~azure.mgmt.netapp.models.Snapshot]
        :raises:
         :class:`ErrorException<azure.mgmt.netapp.models.ErrorException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
                    'resourceGroup': self._serialize.url("resource_group", resource_group, 'str'),
                    'accountName': self._serialize.url("account_name", account_name, 'str'),
                    'poolName': self._serialize.url("pool_name", pool_name, 'str'),
                    'volumeName': self._serialize.url("volume_name", volume_name, 'str')
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
            header_parameters['Accept'] = 'application/json'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.SnapshotPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.SnapshotPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.NetApp/netAppAccounts/{accountName}/pools/{poolName}/volumes/{volumeName}/snapshots'}

    def get(
            self, resource_group, account_name, pool_name, volume_name, snapshot_name, custom_headers=None, raw=False, **operation_config):
        """Get a snapshot.

        :param resource_group: The name of the resource group.
        :type resource_group: str
        :param account_name: The name of the NetApp account
        :type account_name: str
        :param pool_name: The name of the capacity pool
        :type pool_name: str
        :param volume_name: The name of the volume
        :type volume_name: str
        :param snapshot_name: The name of the mount target
        :type snapshot_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: Snapshot or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.netapp.models.Snapshot or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorException<azure.mgmt.netapp.models.ErrorException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroup': self._serialize.url("resource_group", resource_group, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
            'poolName': self._serialize.url("pool_name", pool_name, 'str'),
            'volumeName': self._serialize.url("volume_name", volume_name, 'str'),
            'snapshotName': self._serialize.url("snapshot_name", snapshot_name, 'str')
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
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('Snapshot', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.NetApp/netAppAccounts/{accountName}/pools/{poolName}/volumes/{volumeName}/snapshots/{snapshotName}'}


    def _delete_initial(
            self, resource_group, account_name, pool_name, volume_name, snapshot_name, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str'),
            'resourceGroup': self._serialize.url("resource_group", resource_group, 'str'),
            'accountName': self._serialize.url("account_name", account_name, 'str'),
            'poolName': self._serialize.url("pool_name", pool_name, 'str'),
            'volumeName': self._serialize.url("volume_name", volume_name, 'str'),
            'snapshotName': self._serialize.url("snapshot_name", snapshot_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [202, 204]:
            raise models.ErrorException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response

    def delete(
            self, resource_group, account_name, pool_name, volume_name, snapshot_name, custom_headers=None, raw=False, polling=True, **operation_config):
        """Delete snapshot.

        :param resource_group: The name of the resource group.
        :type resource_group: str
        :param account_name: The name of the NetApp account
        :type account_name: str
        :param pool_name: The name of the capacity pool
        :type pool_name: str
        :param volume_name: The name of the volume
        :type volume_name: str
        :param snapshot_name: The name of the mount target
        :type snapshot_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns None or
         ClientRawResponse<None> if raw==True
        :rtype: ~msrestazure.azure_operation.AzureOperationPoller[None] or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[None]]
        :raises:
         :class:`ErrorException<azure.mgmt.netapp.models.ErrorException>`
        """
        raw_result = self._delete_initial(
            resource_group=resource_group,
            account_name=account_name,
            pool_name=pool_name,
            volume_name=volume_name,
            snapshot_name=snapshot_name,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            if raw:
                client_raw_response = ClientRawResponse(None, response)
                return client_raw_response

        lro_delay = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        if polling is True: polling_method = ARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = NoPolling()
        else: polling_method = polling
        return LROPoller(self._client, raw_result, get_long_running_output, polling_method)
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.NetApp/netAppAccounts/{accountName}/pools/{poolName}/volumes/{volumeName}/snapshots/{snapshotName}'}
