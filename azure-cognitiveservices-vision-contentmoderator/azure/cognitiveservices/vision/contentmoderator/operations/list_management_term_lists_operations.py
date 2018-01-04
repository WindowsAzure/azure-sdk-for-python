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

from msrest.pipeline import ClientRawResponse

from .. import models


class ListManagementTermListsOperations(object):
    """ListManagementTermListsOperations operations.

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

    def get_details(
            self, list_id, custom_headers=None, raw=False, **operation_config):
        """Returns list Id details of the term list with list Id equal to list Id
        passed.

        :param list_id: List Id of the image list.
        :type list_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: TermList or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.vision.contentmoderator.models.TermList or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.contentmoderator.models.APIErrorException>`
        """
        # Construct URL
        url = '/contentmoderator/lists/v1.0/termlists/{listId}'
        path_format_arguments = {
            'baseUrl': self._serialize.url("self.config.base_url", self.config.base_url, 'str', skip_quote=True),
            'listId': self._serialize.url("list_id", list_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.get(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('TermList', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def delete(
            self, list_id, custom_headers=None, raw=False, **operation_config):
        """Deletes term list with the list Id equal to list Id passed.

        :param list_id: List Id of the image list.
        :type list_id: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: str or ClientRawResponse if raw=true
        :rtype: str or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.contentmoderator.models.APIErrorException>`
        """
        # Construct URL
        url = '/contentmoderator/lists/v1.0/termlists/{listId}'
        path_format_arguments = {
            'baseUrl': self._serialize.url("self.config.base_url", self.config.base_url, 'str', skip_quote=True),
            'listId': self._serialize.url("list_id", list_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.delete(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('str', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def update(
            self, list_id, content_type, body, custom_headers=None, raw=False, **operation_config):
        """Updates an Term List.

        :param list_id: List Id of the image list.
        :type list_id: str
        :param content_type: The content type.
        :type content_type: str
        :param body: Schema of the body.
        :type body:
         ~azure.cognitiveservices.vision.contentmoderator.models.Body
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: TermList or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.vision.contentmoderator.models.TermList or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.contentmoderator.models.APIErrorException>`
        """
        # Construct URL
        url = '/contentmoderator/lists/v1.0/termlists/{listId}'
        path_format_arguments = {
            'baseUrl': self._serialize.url("self.config.base_url", self.config.base_url, 'str', skip_quote=True),
            'listId': self._serialize.url("list_id", list_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')

        # Construct body
        body_content = self._serialize.body(body, 'Body')

        # Construct and send request
        request = self._client.put(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('TermList', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def create(
            self, content_type, body, custom_headers=None, raw=False, **operation_config):
        """Creates a Term List.

        :param content_type: The content type.
        :type content_type: str
        :param body: Schema of the body.
        :type body:
         ~azure.cognitiveservices.vision.contentmoderator.models.Body
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: TermList or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.vision.contentmoderator.models.TermList or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.contentmoderator.models.APIErrorException>`
        """
        # Construct URL
        url = '/contentmoderator/lists/v1.0/termlists'
        path_format_arguments = {
            'baseUrl': self._serialize.url("self.config.base_url", self.config.base_url, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')

        # Construct body
        body_content = self._serialize.body(body, 'Body')

        # Construct and send request
        request = self._client.post(url, query_parameters)
        response = self._client.send(
            request, header_parameters, body_content, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('TermList', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def get_all_term_lists(
            self, custom_headers=None, raw=False, **operation_config):
        """gets all the Term Lists.

        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: list or ClientRawResponse if raw=true
        :rtype:
         list[~azure.cognitiveservices.vision.contentmoderator.models.TermList]
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.contentmoderator.models.APIErrorException>`
        """
        # Construct URL
        url = '/contentmoderator/lists/v1.0/termlists'
        path_format_arguments = {
            'baseUrl': self._serialize.url("self.config.base_url", self.config.base_url, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.get(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('[TermList]', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized

    def refresh_index_method(
            self, list_id, language, custom_headers=None, raw=False, **operation_config):
        """Refreshes the index of the list with list Id equal to list ID passed.

        :param list_id: List Id of the image list.
        :type list_id: str
        :param language: Language of the terms.
        :type language: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: RefreshIndex or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.vision.contentmoderator.models.RefreshIndex
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`APIErrorException<azure.cognitiveservices.vision.contentmoderator.models.APIErrorException>`
        """
        # Construct URL
        url = '/contentmoderator/lists/v1.0/termlists/{listId}/RefreshIndex'
        path_format_arguments = {
            'baseUrl': self._serialize.url("self.config.base_url", self.config.base_url, 'str', skip_quote=True),
            'listId': self._serialize.url("list_id", list_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['language'] = self._serialize.query("language", language, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.post(url, query_parameters)
        response = self._client.send(request, header_parameters, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.APIErrorException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('RefreshIndex', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
