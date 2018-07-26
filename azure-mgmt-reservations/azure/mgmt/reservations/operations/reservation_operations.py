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


class ReservationOperations(object):
    """ReservationOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Supported version. Constant value: "2018-06-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-06-01"

        self.config = config


    def _split_initial(
            self, reservation_order_id, quantities=None, reservation_id=None, custom_headers=None, raw=False, **operation_config):
        body = models.SplitRequest(quantities=quantities, reservation_id=reservation_id)

        # Construct URL
        url = self.split.metadata['url']
        path_format_arguments = {
            'reservationOrderId': self._serialize.url("reservation_order_id", reservation_order_id, 'str')
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
        body_content = self._serialize.body(body, 'SplitRequest')

        # Construct and send request
        request = self._client.post(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200, 202]:
            raise models.ErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('[ReservationResponse]', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def split(
            self, reservation_order_id, quantities=None, reservation_id=None, custom_headers=None, raw=False, polling=True, **operation_config):
        """Split the `Reservation`.

        Split a `Reservation` into two `Reservation`s with specified quantity
        distribution.
        .

        :param reservation_order_id: Order Id of the reservation
        :type reservation_order_id: str
        :param quantities: List of the quantities in the new reservations to
         create.
        :type quantities: list[int]
        :param reservation_id: Resource id of the reservation to be split.
         Format of the resource id should be
         /providers/Microsoft.Capacity/reservationOrders/{reservationOrderId}/reservations/{reservationId}
        :type reservation_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns list or
         ClientRawResponse<list> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[list[~azure.mgmt.reservations.models.ReservationResponse]]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[list[~azure.mgmt.reservations.models.ReservationResponse]]]
        :raises:
         :class:`ErrorException<azure.mgmt.reservations.models.ErrorException>`
        """
        raw_result = self._split_initial(
            reservation_order_id=reservation_order_id,
            quantities=quantities,
            reservation_id=reservation_id,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('[ReservationResponse]', response)

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
    split.metadata = {'url': '/providers/Microsoft.Capacity/reservationOrders/{reservationOrderId}/split'}


    def _merge_initial(
            self, reservation_order_id, sources=None, custom_headers=None, raw=False, **operation_config):
        body = models.MergeRequest(sources=sources)

        # Construct URL
        url = self.merge.metadata['url']
        path_format_arguments = {
            'reservationOrderId': self._serialize.url("reservation_order_id", reservation_order_id, 'str')
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
        body_content = self._serialize.body(body, 'MergeRequest')

        # Construct and send request
        request = self._client.post(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200, 202]:
            raise models.ErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('[ReservationResponse]', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def merge(
            self, reservation_order_id, sources=None, custom_headers=None, raw=False, polling=True, **operation_config):
        """Merges two `Reservation`s.

        Merge the specified `Reservation`s into a new `Reservation`. The two
        `Reservation`s being merged must have same properties.

        :param reservation_order_id: Order Id of the reservation
        :type reservation_order_id: str
        :param sources: Format of the resource id should be
         /providers/Microsoft.Capacity/reservationOrders/{reservationOrderId}/reservations/{reservationId}
        :type sources: list[str]
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns list or
         ClientRawResponse<list> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[list[~azure.mgmt.reservations.models.ReservationResponse]]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[list[~azure.mgmt.reservations.models.ReservationResponse]]]
        :raises:
         :class:`ErrorException<azure.mgmt.reservations.models.ErrorException>`
        """
        raw_result = self._merge_initial(
            reservation_order_id=reservation_order_id,
            sources=sources,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('[ReservationResponse]', response)

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
    merge.metadata = {'url': '/providers/Microsoft.Capacity/reservationOrders/{reservationOrderId}/merge'}

    def list(
            self, reservation_order_id, custom_headers=None, raw=False, **operation_config):
        """Get `Reservation`s in a given reservation Order.

        List `Reservation`s within a single `ReservationOrder`.

        :param reservation_order_id: Order Id of the reservation
        :type reservation_order_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of ReservationResponse
        :rtype:
         ~azure.mgmt.reservations.models.ReservationResponsePaged[~azure.mgmt.reservations.models.ReservationResponse]
        :raises:
         :class:`ErrorException<azure.mgmt.reservations.models.ErrorException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list.metadata['url']
                path_format_arguments = {
                    'reservationOrderId': self._serialize.url("reservation_order_id", reservation_order_id, 'str')
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
            request = self._client.get(url, query_parameters)
            response = self._client.send(
                request, header_parameters, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.ReservationResponsePaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.ReservationResponsePaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/providers/Microsoft.Capacity/reservationOrders/{reservationOrderId}/reservations'}

    def get(
            self, reservation_id, reservation_order_id, custom_headers=None, raw=False, **operation_config):
        """Get `Reservation` details.

        Get specific `Reservation` details.

        :param reservation_id: Id of the Reservation Item
        :type reservation_id: str
        :param reservation_order_id: Order Id of the reservation
        :type reservation_order_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ReservationResponse or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.reservations.models.ReservationResponse or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorException<azure.mgmt.reservations.models.ErrorException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'reservationId': self._serialize.url("reservation_id", reservation_id, 'str'),
            'reservationOrderId': self._serialize.url("reservation_order_id", reservation_order_id, 'str')
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
        request = self._client.get(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ReservationResponse', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/providers/Microsoft.Capacity/reservationOrders/{reservationOrderId}/reservations/{reservationId}'}


    def _update_initial(
            self, reservation_order_id, reservation_id, parameters, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.update.metadata['url']
        path_format_arguments = {
            'reservationOrderId': self._serialize.url("reservation_order_id", reservation_order_id, 'str'),
            'reservationId': self._serialize.url("reservation_id", reservation_id, 'str')
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
        body_content = self._serialize.body(parameters, 'Patch')

        # Construct and send request
        request = self._client.patch(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200, 202]:
            raise models.ErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('ReservationResponse', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def update(
            self, reservation_order_id, reservation_id, parameters, custom_headers=None, raw=False, polling=True, **operation_config):
        """Updates a `Reservation`.

        Updates the applied scopes of the `Reservation`.

        :param reservation_order_id: Order Id of the reservation
        :type reservation_order_id: str
        :param reservation_id: Id of the Reservation Item
        :type reservation_id: str
        :param parameters: Information needed to patch a reservation item
        :type parameters: ~azure.mgmt.reservations.models.Patch
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns ReservationResponse or
         ClientRawResponse<ReservationResponse> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.reservations.models.ReservationResponse]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.reservations.models.ReservationResponse]]
        :raises:
         :class:`ErrorException<azure.mgmt.reservations.models.ErrorException>`
        """
        raw_result = self._update_initial(
            reservation_order_id=reservation_order_id,
            reservation_id=reservation_id,
            parameters=parameters,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('ReservationResponse', response)

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
    update.metadata = {'url': '/providers/Microsoft.Capacity/reservationOrders/{reservationOrderId}/reservations/{reservationId}'}

    def list_revisions(
            self, reservation_id, reservation_order_id, custom_headers=None, raw=False, **operation_config):
        """Get `Reservation` revisions.

        List of all the revisions for the `Reservation`.
        .

        :param reservation_id: Id of the Reservation Item
        :type reservation_id: str
        :param reservation_order_id: Order Id of the reservation
        :type reservation_order_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of ReservationResponse
        :rtype:
         ~azure.mgmt.reservations.models.ReservationResponsePaged[~azure.mgmt.reservations.models.ReservationResponse]
        :raises:
         :class:`ErrorException<azure.mgmt.reservations.models.ErrorException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = self.list_revisions.metadata['url']
                path_format_arguments = {
                    'reservationId': self._serialize.url("reservation_id", reservation_id, 'str'),
                    'reservationOrderId': self._serialize.url("reservation_order_id", reservation_order_id, 'str')
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
            request = self._client.get(url, query_parameters)
            response = self._client.send(
                request, header_parameters, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.ReservationResponsePaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.ReservationResponsePaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
    list_revisions.metadata = {'url': '/providers/Microsoft.Capacity/reservationOrders/{reservationOrderId}/reservations/{reservationId}/revisions'}
