# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

import uuid
from msrest.pipeline import ClientRawResponse

from .. import models


class ReservationsSummariesOperations(object):
    """ReservationsSummariesOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An objec model deserializer.
    :ivar api_version: Version of the API to be used with the client request. The current version is 2018-01-31. Constant value: "2018-01-31".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2018-01-31"

        self.config = config

    def list_by_reservation_order(
            self, reservation_order_id, grain, filter=None, custom_headers=None, raw=False, **operation_config):
        """Lists the reservations summaries for daily or monthly grain.

        :param reservation_order_id: Order Id of the reservation
        :type reservation_order_id: str
        :param grain: Can be daily or monthly. Possible values include:
         'DailyGrain', 'MonthlyGrain'
        :type grain: str or ~consumption.models.Datagrain
        :param filter: Required only for daily grain. The properties/UsageDate
         for start date and end date. The filter supports 'le' and  'ge'
        :type filter: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of ReservationSummaries
        :rtype:
         ~consumption.models.ReservationSummariesPaged[~consumption.models.ReservationSummaries]
        :raises:
         :class:`ErrorResponseException<consumption.models.ErrorResponseException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = '/providers/Microsoft.Capacity/reservationorders/{reservationOrderId}/providers/Microsoft.Consumption/reservationSummaries'
                path_format_arguments = {
                    'reservationOrderId': self._serialize.url("reservation_order_id", reservation_order_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['grain'] = self._serialize.query("grain", grain, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
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
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.ReservationSummariesPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.ReservationSummariesPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized

    def list_by_reservation_order_and_reservation(
            self, reservation_order_id, reservation_id, grain, filter=None, custom_headers=None, raw=False, **operation_config):
        """Lists the reservations summaries for daily or monthly grain.

        :param reservation_order_id: Order Id of the reservation
        :type reservation_order_id: str
        :param reservation_id: Id of the reservation
        :type reservation_id: str
        :param grain: Can be daily or monthly. Possible values include:
         'DailyGrain', 'MonthlyGrain'
        :type grain: str or ~consumption.models.Datagrain
        :param filter: Required only for daily grain. The properties/UsageDate
         for start date and end date. The filter supports 'le' and  'ge'
        :type filter: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of ReservationSummaries
        :rtype:
         ~consumption.models.ReservationSummariesPaged[~consumption.models.ReservationSummaries]
        :raises:
         :class:`ErrorResponseException<consumption.models.ErrorResponseException>`
        """
        def internal_paging(next_link=None, raw=False):

            if not next_link:
                # Construct URL
                url = '/providers/Microsoft.Capacity/reservationorders/{reservationOrderId}/reservations/{reservationId}/providers/Microsoft.Consumption/reservationSummaries'
                path_format_arguments = {
                    'reservationOrderId': self._serialize.url("reservation_order_id", reservation_order_id, 'str'),
                    'reservationId': self._serialize.url("reservation_id", reservation_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                query_parameters['grain'] = self._serialize.query("grain", grain, 'str')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
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
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        deserialized = models.ReservationSummariesPaged(internal_paging, self._deserialize.dependencies)

        if raw:
            header_dict = {}
            client_raw_response = models.ReservationSummariesPaged(internal_paging, self._deserialize.dependencies, header_dict)
            return client_raw_response

        return deserialized
