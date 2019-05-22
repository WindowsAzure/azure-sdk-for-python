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


class FeaturesOperations(object):
    """FeaturesOperations operations.

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

    def list_application_version_pattern_features(
            self, app_id, version_id, skip=0, take=100, custom_headers=None, raw=False, **operation_config):
        """[DEPRECATED NOTICE: This operation will soon be removed] Gets all the
        pattern features.

        :param app_id: The application ID.
        :type app_id: str
        :param version_id: The version ID.
        :type version_id: str
        :param skip: The number of entries to skip. Default value is 0.
        :type skip: int
        :param take: The number of entries to return. Maximum page size is
         500. Default is 100.
        :type take: int
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: list or ClientRawResponse if raw=true
        :rtype:
         list[~azure.cognitiveservices.language.luis.authoring.models.PatternFeatureInfo]
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.language.luis.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.list_application_version_pattern_features.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'appId': self._serialize.url("app_id", app_id, 'str'),
            'versionId': self._serialize.url("version_id", version_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if skip is not None:
            query_parameters['skip'] = self._serialize.query("skip", skip, 'int', minimum=0)
        if take is not None:
            query_parameters['take'] = self._serialize.query("take", take, 'int', maximum=500, minimum=0)

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
            deserialized = self._deserialize('[PatternFeatureInfo]', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_application_version_pattern_features.metadata = {'url': '/apps/{appId}/versions/{versionId}/patterns'}

    def add_phrase_list(
            self, app_id, version_id, phraselist_create_object, custom_headers=None, raw=False, **operation_config):
        """Creates a new phraselist feature in a version of the application.

        :param app_id: The application ID.
        :type app_id: str
        :param version_id: The version ID.
        :type version_id: str
        :param phraselist_create_object: A Phraselist object containing Name,
         comma-separated Phrases and the isExchangeable boolean. Default value
         for isExchangeable is true.
        :type phraselist_create_object:
         ~azure.cognitiveservices.language.luis.authoring.models.PhraselistCreateObject
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: int or ClientRawResponse if raw=true
        :rtype: int or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.language.luis.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.add_phrase_list.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'appId': self._serialize.url("app_id", app_id, 'str'),
            'versionId': self._serialize.url("version_id", version_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(phraselist_create_object, 'PhraselistCreateObject')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [201]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 201:
            deserialized = self._deserialize('int', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    add_phrase_list.metadata = {'url': '/apps/{appId}/versions/{versionId}/phraselists'}

    def list_phrase_lists(
            self, app_id, version_id, skip=0, take=100, custom_headers=None, raw=False, **operation_config):
        """Gets all the phraselist features in a version of the application.

        :param app_id: The application ID.
        :type app_id: str
        :param version_id: The version ID.
        :type version_id: str
        :param skip: The number of entries to skip. Default value is 0.
        :type skip: int
        :param take: The number of entries to return. Maximum page size is
         500. Default is 100.
        :type take: int
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: list or ClientRawResponse if raw=true
        :rtype:
         list[~azure.cognitiveservices.language.luis.authoring.models.PhraseListFeatureInfo]
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.language.luis.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.list_phrase_lists.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'appId': self._serialize.url("app_id", app_id, 'str'),
            'versionId': self._serialize.url("version_id", version_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if skip is not None:
            query_parameters['skip'] = self._serialize.query("skip", skip, 'int', minimum=0)
        if take is not None:
            query_parameters['take'] = self._serialize.query("take", take, 'int', maximum=500, minimum=0)

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
            deserialized = self._deserialize('[PhraseListFeatureInfo]', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list_phrase_lists.metadata = {'url': '/apps/{appId}/versions/{versionId}/phraselists'}

    def list(
            self, app_id, version_id, skip=0, take=100, custom_headers=None, raw=False, **operation_config):
        """Gets all the extraction phraselist and pattern features in a version of
        the application.

        :param app_id: The application ID.
        :type app_id: str
        :param version_id: The version ID.
        :type version_id: str
        :param skip: The number of entries to skip. Default value is 0.
        :type skip: int
        :param take: The number of entries to return. Maximum page size is
         500. Default is 100.
        :type take: int
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: FeaturesResponseObject or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.language.luis.authoring.models.FeaturesResponseObject
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.language.luis.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.list.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'appId': self._serialize.url("app_id", app_id, 'str'),
            'versionId': self._serialize.url("version_id", version_id, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if skip is not None:
            query_parameters['skip'] = self._serialize.query("skip", skip, 'int', minimum=0)
        if take is not None:
            query_parameters['take'] = self._serialize.query("take", take, 'int', maximum=500, minimum=0)

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
            deserialized = self._deserialize('FeaturesResponseObject', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    list.metadata = {'url': '/apps/{appId}/versions/{versionId}/features'}

    def get_phrase_list(
            self, app_id, version_id, phraselist_id, custom_headers=None, raw=False, **operation_config):
        """Gets phraselist feature info in a version of the application.

        :param app_id: The application ID.
        :type app_id: str
        :param version_id: The version ID.
        :type version_id: str
        :param phraselist_id: The ID of the feature to be retrieved.
        :type phraselist_id: int
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: PhraseListFeatureInfo or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.language.luis.authoring.models.PhraseListFeatureInfo
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.language.luis.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get_phrase_list.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'appId': self._serialize.url("app_id", app_id, 'str'),
            'versionId': self._serialize.url("version_id", version_id, 'str'),
            'phraselistId': self._serialize.url("phraselist_id", phraselist_id, 'int')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

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
            deserialized = self._deserialize('PhraseListFeatureInfo', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    get_phrase_list.metadata = {'url': '/apps/{appId}/versions/{versionId}/phraselists/{phraselistId}'}

    def update_phrase_list(
            self, app_id, version_id, phraselist_id, phraselist_update_object=None, custom_headers=None, raw=False, **operation_config):
        """Updates the phrases, the state and the name of the phraselist feature
        in a version of the application.

        :param app_id: The application ID.
        :type app_id: str
        :param version_id: The version ID.
        :type version_id: str
        :param phraselist_id: The ID of the feature to be updated.
        :type phraselist_id: int
        :param phraselist_update_object: The new values for: - Just a boolean
         called IsActive, in which case the status of the feature will be
         changed. - Name, Pattern, Mode, and a boolean called IsActive to
         update the feature.
        :type phraselist_update_object:
         ~azure.cognitiveservices.language.luis.authoring.models.PhraselistUpdateObject
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: OperationStatus or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.language.luis.authoring.models.OperationStatus
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.language.luis.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.update_phrase_list.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'appId': self._serialize.url("app_id", app_id, 'str'),
            'versionId': self._serialize.url("version_id", version_id, 'str'),
            'phraselistId': self._serialize.url("phraselist_id", phraselist_id, 'int')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        if phraselist_update_object is not None:
            body_content = self._serialize.body(phraselist_update_object, 'PhraselistUpdateObject')
        else:
            body_content = None

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('OperationStatus', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    update_phrase_list.metadata = {'url': '/apps/{appId}/versions/{versionId}/phraselists/{phraselistId}'}

    def delete_phrase_list(
            self, app_id, version_id, phraselist_id, custom_headers=None, raw=False, **operation_config):
        """Deletes a phraselist feature from a version of the application.

        :param app_id: The application ID.
        :type app_id: str
        :param version_id: The version ID.
        :type version_id: str
        :param phraselist_id: The ID of the feature to be deleted.
        :type phraselist_id: int
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: OperationStatus or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.language.luis.authoring.models.OperationStatus
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.cognitiveservices.language.luis.authoring.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.delete_phrase_list.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True),
            'appId': self._serialize.url("app_id", app_id, 'str'),
            'versionId': self._serialize.url("version_id", version_id, 'str'),
            'phraselistId': self._serialize.url("phraselist_id", phraselist_id, 'int')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        deserialized = None

        if response.status_code == 200:
            deserialized = self._deserialize('OperationStatus', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    delete_phrase_list.metadata = {'url': '/apps/{appId}/versions/{versionId}/phraselists/{phraselistId}'}
