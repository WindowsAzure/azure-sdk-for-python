# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.pipeline import ClientRawResponse

from .. import models


class RegistrationAssignmentsOperations(object):
    """RegistrationAssignmentsOperations operations.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer

        self.config = config

    def get(
            self, scope, registration_assignment_id, api_version, expand_registration_definition=None, custom_headers=None, raw=False, **operation_config):
        """Gets the details of specified registration assignment.

        :param scope: Scope of the resource.
        :type scope: str
        :param registration_assignment_id: Guid of the registration
         assignment.
        :type registration_assignment_id: str
        :param api_version: The API version to use for this operation.
        :type api_version: str
        :param expand_registration_definition: Tells whether to return
         registration definition details also along with registration
         assignment details.
        :type expand_registration_definition: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: RegistrationAssignment or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.managedservices.models.RegistrationAssignment or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.managedservices.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'registrationAssignmentId': self._serialize.url("registration_assignment_id", registration_assignment_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if expand_registration_definition is not None:
            query_parameters['$expandRegistrationDefinition'] = self._serialize.query("expand_registration_definition", expand_registration_definition, 'bool')
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('RegistrationAssignment', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get.metadata = {'url': '/{scope}/providers/Microsoft.ManagedServices/registrationAssignments/{registrationAssignmentId}'}

    def delete(
            self, scope, registration_assignment_id, api_version, custom_headers=None, raw=False, **operation_config):
        """Deletes the specified registration assignment.

        :param scope: Scope of the resource.
        :type scope: str
        :param registration_assignment_id: Guid of the registration
         assignment.
        :type registration_assignment_id: str
        :param api_version: The API version to use for this operation.
        :type api_version: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: None or ClientRawResponse if raw=true
        :rtype: None or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.managedservices.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'registrationAssignmentId': self._serialize.url("registration_assignment_id", registration_assignment_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 202, 204]:
            raise models.ErrorResponseException(self._deserialize, response)

        if raw:
            client_raw_response = ClientRawResponse(None, response)
            return client_raw_response
    delete.metadata = {'url': '/{scope}/providers/Microsoft.ManagedServices/registrationAssignments/{registrationAssignmentId}'}

    def create_or_update(
            self, scope, registration_assignment_id, api_version, request_body, custom_headers=None, raw=False, **operation_config):
        """Creates or updates a registration assignment.

        :param scope: Scope of the resource.
        :type scope: str
        :param registration_assignment_id: Guid of the registration
         assignment.
        :type registration_assignment_id: str
        :param api_version: The API version to use for this operation.
        :type api_version: str
        :param request_body: The parameters required to create new
         registration assignment.
        :type request_body:
         ~azure.mgmt.managedservices.models.RegistrationAssignment
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: RegistrationAssignment or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.managedservices.models.RegistrationAssignment or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.managedservices.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.create_or_update.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True),
            'registrationAssignmentId': self._serialize.url("registration_assignment_id", registration_assignment_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(request_body, 'RegistrationAssignment')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200, 201]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('RegistrationAssignment', response)
        if response.status_code == 201:
            deserialized = self._deserialize('RegistrationAssignment', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    create_or_update.metadata = {'url': '/{scope}/providers/Microsoft.ManagedServices/registrationAssignments/{registrationAssignmentId}'}

    def list(
            self, scope, api_version, expand_registration_definition=None, custom_headers=None, raw=False, **operation_config):
        """Gets a list of the registration assignments.

        :param scope: Scope of the resource.
        :type scope: str
        :param api_version: The API version to use for this operation.
        :type api_version: str
        :param expand_registration_definition: Tells whether to return
         registration definition details also along with registration
         assignment details.
        :type expand_registration_definition: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: RegistrationAssignmentList or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.managedservices.models.RegistrationAssignmentList
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.managedservices.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.list.metadata['url']
        path_format_arguments = {
            'scope': self._serialize.url("scope", scope, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if expand_registration_definition is not None:
            query_parameters['$expandRegistrationDefinition'] = self._serialize.query("expand_registration_definition", expand_registration_definition, 'bool')
        query_parameters['api-version'] = self._serialize.query("api_version", api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('RegistrationAssignmentList', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/{scope}/providers/Microsoft.ManagedServices/registrationAssignments'}
