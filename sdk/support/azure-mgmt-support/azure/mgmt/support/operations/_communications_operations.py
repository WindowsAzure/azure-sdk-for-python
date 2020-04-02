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


class CommunicationsOperations(object):
    """CommunicationsOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: Api version. Constant value: "2020-04-01".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2020-04-01"

        self.config = config

    def check_name_availability(
            self, support_ticket_name, name, type, custom_headers=None, raw=False, **operation_config):
        """Check the availability of a resource name. This API should to be used
        to check the uniqueness of the name for adding a new communication to
        the support ticket.

        :param support_ticket_name: Support ticket name
        :type support_ticket_name: str
        :param name: The resource name to validate
        :type name: str
        :param type: The type of resource. Possible values include:
         'Microsoft.Support/supportTickets', 'Microsoft.Support/communications'
        :type type: str or ~azure.mgmt.support.models.Type
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: CheckNameAvailabilityOutput or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.support.models.CheckNameAvailabilityOutput or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ExceptionResponseException<azure.mgmt.support.models.ExceptionResponseException>`
        """
        check_name_availability_input = models.CheckNameAvailabilityInput(name=name, type=type)

        # Construct URL
        url = self.check_name_availability.metadata['url']
        path_format_arguments = {
            'supportTicketName': self._serialize.url("support_ticket_name", support_ticket_name, 'str'),
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
        body_content = self._serialize.body(check_name_availability_input, 'CheckNameAvailabilityInput')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ExceptionResponseException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('CheckNameAvailabilityOutput', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    check_name_availability.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Support/supportTickets/{supportTicketName}/checkNameAvailability'}

    def list(
            self, support_ticket_name, top=None, filter=None, custom_headers=None, raw=False, **operation_config):
        """Lists all communications (attachments not included) for a support
        ticket. <br/></br> You can also filter support ticket communications by
        _CreatedDate_ or _CommunicationType_ using the $filter parameter. The
        only type of communication supported today is _Web_. Output will be a
        paged result with _nextLink_, using which you can retrieve the next set
        of Communication results. <br/><br/>Support ticket data is available
        for 12 months after ticket creation. If a ticket was created more than
        12 months ago, a request for data might cause an error.

        :param support_ticket_name: Support ticket name
        :type support_ticket_name: str
        :param top: The number of values to return in the collection. Default
         is 10 and max is 10.
        :type top: int
        :param filter: The filter to apply on the operation. You can filter by
         communicationType and createdDate properties. CommunicationType
         supports Equals ('eq') operator and createdDate supports Greater Than
         ('gt') and Greater Than or Equals ('ge') operators. You may combine
         the CommunicationType and CreatedDate filters by Logical And ('and')
         operator.
        :type filter: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of CommunicationDetails
        :rtype:
         ~azure.mgmt.support.models.CommunicationDetailsPaged[~azure.mgmt.support.models.CommunicationDetails]
        :raises:
         :class:`ExceptionResponseException<azure.mgmt.support.models.ExceptionResponseException>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list.metadata['url']
                path_format_arguments = {
                    'supportTicketName': self._serialize.url("support_ticket_name", support_ticket_name, 'str'),
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if top is not None:
                    query_parameters['$top'] = self._serialize.query("top", top, 'int')
                if filter is not None:
                    query_parameters['$filter'] = self._serialize.query("filter", filter, 'str')
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
            return request

        def internal_paging(next_link=None):
            request = prepare_request(next_link)

            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ExceptionResponseException(self._deserialize, response)

            return response

        # Deserialize response
        header_dict = None
        if raw:
            header_dict = {}
        deserialized = models.CommunicationDetailsPaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Support/supportTickets/{supportTicketName}/communications'}

    def get(
            self, support_ticket_name, communication_name, custom_headers=None, raw=False, **operation_config):
        """Returns communication details for a support ticket.

        :param support_ticket_name: Support ticket name
        :type support_ticket_name: str
        :param communication_name: Communication name
        :type communication_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: CommunicationDetails or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.support.models.CommunicationDetails or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ExceptionResponseException<azure.mgmt.support.models.ExceptionResponseException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'supportTicketName': self._serialize.url("support_ticket_name", support_ticket_name, 'str'),
            'communicationName': self._serialize.url("communication_name", communication_name, 'str'),
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
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ExceptionResponseException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('CommunicationDetails', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Support/supportTickets/{supportTicketName}/communications/{communicationName}'}


    def _create_initial(
            self, support_ticket_name, communication_name, create_communication_parameters, custom_headers=None, raw=False, **operation_config):
        # Construct URL
        url = self.create.metadata['url']
        path_format_arguments = {
            'supportTicketName': self._serialize.url("support_ticket_name", support_ticket_name, 'str'),
            'communicationName': self._serialize.url("communication_name", communication_name, 'str'),
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
        body_content = self._serialize.body(create_communication_parameters, 'CommunicationDetails')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 202]:
            raise models.ExceptionResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('CommunicationDetails', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def create(
            self, support_ticket_name, communication_name, create_communication_parameters, custom_headers=None, raw=False, polling=True, **operation_config):
        """Adds a new customer communication to an Azure support ticket.

        :param support_ticket_name: Support ticket name
        :type support_ticket_name: str
        :param communication_name: Communication name
        :type communication_name: str
        :param create_communication_parameters: Communication object
        :type create_communication_parameters:
         ~azure.mgmt.support.models.CommunicationDetails
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: The poller return type is ClientRawResponse, the
         direct response alongside the deserialized response
        :param polling: True for ARMPolling, False for no polling, or a
         polling object for personal polling strategy
        :return: An instance of LROPoller that returns CommunicationDetails or
         ClientRawResponse<CommunicationDetails> if raw==True
        :rtype:
         ~msrestazure.azure_operation.AzureOperationPoller[~azure.mgmt.support.models.CommunicationDetails]
         or
         ~msrestazure.azure_operation.AzureOperationPoller[~msrest.pipeline.ClientRawResponse[~azure.mgmt.support.models.CommunicationDetails]]
        :raises:
         :class:`ExceptionResponseException<azure.mgmt.support.models.ExceptionResponseException>`
        """
        raw_result = self._create_initial(
            support_ticket_name=support_ticket_name,
            communication_name=communication_name,
            create_communication_parameters=create_communication_parameters,
            custom_headers=custom_headers,
            raw=True,
            **operation_config
        )

        def get_long_running_output(response):
            deserialized = self._deserialize('CommunicationDetails', response)

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
    create.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.Support/supportTickets/{supportTicketName}/communications/{communicationName}'}
