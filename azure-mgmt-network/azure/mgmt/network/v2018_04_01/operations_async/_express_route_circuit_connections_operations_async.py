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
from msrest.polling.async_poller import async_poller, AsyncNoPolling
from msrestazure.polling.async_arm_polling import AsyncARMPolling

from .. import models


class ExpressRouteCircuitConnectionsOperations:
    """ExpressRouteCircuitConnectionsOperations async operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Client API version. Constant value: "2018-04-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer) -> None:

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-04-01"

        self.config = config


    async def _delete_initial(
            self, resource_group_name, circuit_name, peering_name, connection_name, *, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'circuitName': self._serialize.url("circuit_name", circuit_name, 'str'),
            'peeringName': self._serialize.url("peering_name", peering_name, 'str'),
            'connectionName': self._serialize.url("connection_name", connection_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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
        response = await self._client.async_send(request, stream=False, **operation_config)

        if response.status_code not in [200, 202, 204]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response

    async def delete(
            self, resource_group_name, circuit_name, peering_name, connection_name, *, custom_headers=None, raw=False, polling=True, **operation_config):
        """Deletes the specified Express Route Circuit Connection from the
        specified express route circuit.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param circuit_name: The name of the express route circuit.
        :type circuit_name: str
        :param peering_name: The name of the peering.
        :type peering_name: str
        :param connection_name: The name of the express route circuit
         connection.
        :type connection_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for AsyncARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of None or ClientRawResponse<None> if raw==True
        :rtype: ~None or ~msrest.pipeline.ClientRawResponse[None]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        raw_result = await self._delete_initial(
            resource_group_name=resource_group_name,
            circuit_name=circuit_name,
            peering_name=peering_name,
            connection_name=connection_name,
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
        if polling is True: polling_method = AsyncARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = AsyncNoPolling()
        else: polling_method = polling
        return await async_poller(self._client, raw_result, get_long_running_output, polling_method)
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/expressRouteCircuits/{circuitName}/peerings/{peeringName}/connections/{connectionName}'}

    async def get(
            self, resource_group_name, circuit_name, peering_name, connection_name, *, custom_headers=None, raw=False, **operation_config):
        """Gets the specified Express Route Circuit Connection from the specified
        express route circuit.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param circuit_name: The name of the express route circuit.
        :type circuit_name: str
        :param peering_name: The name of the peering.
        :type peering_name: str
        :param connection_name: The name of the express route circuit
         connection.
        :type connection_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ExpressRouteCircuitConnection or ClientRawResponse if
         raw=true
        :rtype:
         ~azure.mgmt.network.v2018_04_01.models.ExpressRouteCircuitConnection
         or ~msrest.pipeline.ClientRawResponse
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'circuitName': self._serialize.url("circuit_name", circuit_name, 'str'),
            'peeringName': self._serialize.url("peering_name", peering_name, 'str'),
            'connectionName': self._serialize.url("connection_name", connection_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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
        response = await self._client.async_send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('ExpressRouteCircuitConnection', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/expressRouteCircuits/{circuitName}/peerings/{peeringName}/connections/{connectionName}'}


    async def _create_or_update_initial(
            self, resource_group_name, circuit_name, peering_name, connection_name, express_route_circuit_connection_parameters, *, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.create_or_update.metadata['url']
        path_format_arguments = {
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'circuitName': self._serialize.url("circuit_name", circuit_name, 'str'),
            'peeringName': self._serialize.url("peering_name", peering_name, 'str'),
            'connectionName': self._serialize.url("connection_name", connection_name, 'str'),
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
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
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(express_route_circuit_connection_parameters, 'ExpressRouteCircuitConnection')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = await self._client.async_send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            exp = CloudError(response)
            exp.request_id = response.headers.get('x-ms-request-id')
            raise exp

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ExpressRouteCircuitConnection', response)
        if response.status_code == 201:
            deserialized = self._deserialize('ExpressRouteCircuitConnection', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    async def create_or_update(
            self, resource_group_name, circuit_name, peering_name, connection_name, express_route_circuit_connection_parameters, *, custom_headers=None, raw=False, polling=True, **operation_config):
        """Creates or updates a Express Route Circuit Connection in the specified
        express route circuits.

        :param resource_group_name: The name of the resource group.
        :type resource_group_name: str
        :param circuit_name: The name of the express route circuit.
        :type circuit_name: str
        :param peering_name: The name of the peering.
        :type peering_name: str
        :param connection_name: The name of the express route circuit
         connection.
        :type connection_name: str
        :param express_route_circuit_connection_parameters: Parameters
         supplied to the create or update express route circuit connection
         operation.
        :type express_route_circuit_connection_parameters:
         ~azure.mgmt.network.v2018_04_01.models.ExpressRouteCircuitConnection
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for AsyncARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of ExpressRouteCircuitConnection or
         ClientRawResponse<ExpressRouteCircuitConnection> if raw==True
        :rtype:
         ~~azure.mgmt.network.v2018_04_01.models.ExpressRouteCircuitConnection
         or
         ~msrest.pipeline.ClientRawResponse[~azure.mgmt.network.v2018_04_01.models.ExpressRouteCircuitConnection]
        :raises: :class:`CloudError<msrestazure.azure_exceptions.CloudError>`
        """
        raw_result = await self._create_or_update_initial(
            resource_group_name=resource_group_name,
            circuit_name=circuit_name,
            peering_name=peering_name,
            connection_name=connection_name,
            express_route_circuit_connection_parameters=express_route_circuit_connection_parameters,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('ExpressRouteCircuitConnection', response)

            if raw:
                client_raw_response = ClientRawResponse(deserialized, response)
                return client_raw_response

            return deserialized

        lro_delay = operation_config.get(
            'long_running_operation_timeout',
            self.config.long_running_operation_timeout)
        if polling is True: polling_method = AsyncARMPolling(lro_delay, **operation_config)
        elif polling is False: polling_method = AsyncNoPolling()
        else: polling_method = polling
        return await async_poller(self._client, raw_result, get_long_running_output, polling_method)
    create_or_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/expressRouteCircuits/{circuitName}/peerings/{peeringName}/connections/{connectionName}'}
