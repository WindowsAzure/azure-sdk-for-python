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


class TextAnalyticsClientOperationsMixin(object):

    def entities_recognition_general(
            self, documents, model_version=None, show_stats=None, custom_headers=None, raw=False, **operation_config):
        """Named Entity Recognition.

        The API returns a list of general named entities in a given document.
        For the list of supported entity types, check <a
        href="https://aka.ms/taner">Supported Entity Types in Text Analytics
        API</a>. See the <a href="https://aka.ms/talangs">Supported languages
        in Text Analytics API</a> for the list of enabled languages.

        :param documents: The set of documents to process as part of this
         batch.
        :type documents:
         list[~azure.cognitiveservices.language.textanalytics.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will
         be used for scoring. If a model-version is not specified, the API
         should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain
         input and document level statistics.
        :type show_stats: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: EntitiesResult or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.language.textanalytics.models.EntitiesResult
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`TextAnalyticsErrorException<azure.cognitiveservices.language.textanalytics.models.TextAnalyticsErrorException>`
        """
        input = models.MultiLanguageBatchInput(documents=documents)

        # Construct URL
        url = self.entities_recognition_general.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if model_version is not None:
            query_parameters['model-version'] = self._serialize.query("model_version", model_version, 'str')
        if show_stats is not None:
            query_parameters['showStats'] = self._serialize.query("show_stats", show_stats, 'bool')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(input, 'MultiLanguageBatchInput')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.TextAnalyticsErrorException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('EntitiesResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    entities_recognition_general.metadata = {'url': '/entities/recognition/general'}

    def entities_recognition_pii(
            self, documents, model_version=None, show_stats=None, custom_headers=None, raw=False, **operation_config):
        """Entities containing personal information.

        The API returns a list of entities with personal information (\"SSN\",
        \"Bank Account\" etc) in the document. For the list of supported entity
        types, check <a href="https://aka.ms/tanerpii">Supported Entity Types
        in Text Analytics API</a>. See the <a
        href="https://aka.ms/talangs">Supported languages in Text Analytics
        API</a> for the list of enabled languages.
        .

        :param documents: The set of documents to process as part of this
         batch.
        :type documents:
         list[~azure.cognitiveservices.language.textanalytics.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will
         be used for scoring. If a model-version is not specified, the API
         should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain
         input and document level statistics.
        :type show_stats: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: EntitiesResult or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.language.textanalytics.models.EntitiesResult
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`TextAnalyticsErrorException<azure.cognitiveservices.language.textanalytics.models.TextAnalyticsErrorException>`
        """
        input = models.MultiLanguageBatchInput(documents=documents)

        # Construct URL
        url = self.entities_recognition_pii.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if model_version is not None:
            query_parameters['model-version'] = self._serialize.query("model_version", model_version, 'str')
        if show_stats is not None:
            query_parameters['showStats'] = self._serialize.query("show_stats", show_stats, 'bool')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(input, 'MultiLanguageBatchInput')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.TextAnalyticsErrorException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('EntitiesResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    entities_recognition_pii.metadata = {'url': '/entities/recognition/pii'}

    def entities_linking(
            self, documents, model_version=None, show_stats=None, custom_headers=None, raw=False, **operation_config):
        """Linked entities from a well-known knowledge base.

        The API returns a list of recognized entities with links to a
        well-known knowledge base. See the <a
        href="https://aka.ms/talangs">Supported languages in Text Analytics
        API</a> for the list of enabled languages.

        :param documents: The set of documents to process as part of this
         batch.
        :type documents:
         list[~azure.cognitiveservices.language.textanalytics.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will
         be used for scoring. If a model-version is not specified, the API
         should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain
         input and document level statistics.
        :type show_stats: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: EntityLinkingResult or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.language.textanalytics.models.EntityLinkingResult
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`TextAnalyticsErrorException<azure.cognitiveservices.language.textanalytics.models.TextAnalyticsErrorException>`
        """
        input = models.MultiLanguageBatchInput(documents=documents)

        # Construct URL
        url = self.entities_linking.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if model_version is not None:
            query_parameters['model-version'] = self._serialize.query("model_version", model_version, 'str')
        if show_stats is not None:
            query_parameters['showStats'] = self._serialize.query("show_stats", show_stats, 'bool')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(input, 'MultiLanguageBatchInput')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.TextAnalyticsErrorException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('EntityLinkingResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    entities_linking.metadata = {'url': '/entities/linking'}

    def key_phrases(
            self, documents, model_version=None, show_stats=None, custom_headers=None, raw=False, **operation_config):
        """Key Phrases.

        The API returns a list of strings denoting the key phrases in the input
        text. See the <a href="https://aka.ms/talangs">Supported languages in
        Text Analytics API</a> for the list of enabled languages.

        :param documents: The set of documents to process as part of this
         batch.
        :type documents:
         list[~azure.cognitiveservices.language.textanalytics.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will
         be used for scoring. If a model-version is not specified, the API
         should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain
         input and document level statistics.
        :type show_stats: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: KeyPhraseResult or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.language.textanalytics.models.KeyPhraseResult
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`TextAnalyticsErrorException<azure.cognitiveservices.language.textanalytics.models.TextAnalyticsErrorException>`
        """
        input = models.MultiLanguageBatchInput(documents=documents)

        # Construct URL
        url = self.key_phrases.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if model_version is not None:
            query_parameters['model-version'] = self._serialize.query("model_version", model_version, 'str')
        if show_stats is not None:
            query_parameters['showStats'] = self._serialize.query("show_stats", show_stats, 'bool')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(input, 'MultiLanguageBatchInput')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.TextAnalyticsErrorException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('KeyPhraseResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    key_phrases.metadata = {'url': '/keyPhrases'}

    def languages(
            self, documents, model_version=None, show_stats=None, custom_headers=None, raw=False, **operation_config):
        """Detect Language.

        The API returns the detected language and a numeric score between 0 and
        1. Scores close to 1 indicate 100% certainty that the identified
        language is true. See the <a href="https://aka.ms/talangs">Supported
        languages in Text Analytics API</a> for the list of enabled languages.

        :param documents:
        :type documents:
         list[~azure.cognitiveservices.language.textanalytics.models.LanguageInput]
        :param model_version: (Optional) This value indicates which model will
         be used for scoring. If a model-version is not specified, the API
         should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain
         input and document level statistics.
        :type show_stats: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: LanguageResult or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.language.textanalytics.models.LanguageResult
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`TextAnalyticsErrorException<azure.cognitiveservices.language.textanalytics.models.TextAnalyticsErrorException>`
        """
        input = models.LanguageBatchInput(documents=documents)

        # Construct URL
        url = self.languages.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if model_version is not None:
            query_parameters['model-version'] = self._serialize.query("model_version", model_version, 'str')
        if show_stats is not None:
            query_parameters['showStats'] = self._serialize.query("show_stats", show_stats, 'bool')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(input, 'LanguageBatchInput')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.TextAnalyticsErrorException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('LanguageResult', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    languages.metadata = {'url': '/languages'}

    def sentiment(
            self, documents, model_version=None, show_stats=None, custom_headers=None, raw=False, **operation_config):
        """Sentiment.

        The API returns a sentiment prediction, as well as sentiment scores for
        each sentiment class (Positive, Negative, and Neutral) for the document
        and each sentence within it. See the <a
        href="https://aka.ms/talangs">Supported languages in Text Analytics
        API</a> for the list of enabled languages.

        :param documents: The set of documents to process as part of this
         batch.
        :type documents:
         list[~azure.cognitiveservices.language.textanalytics.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will
         be used for scoring. If a model-version is not specified, the API
         should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain
         input and document level statistics.
        :type show_stats: bool
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: SentimentResponse or ClientRawResponse if raw=true
        :rtype:
         ~azure.cognitiveservices.language.textanalytics.models.SentimentResponse
         or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`TextAnalyticsErrorException<azure.cognitiveservices.language.textanalytics.models.TextAnalyticsErrorException>`
        """
        input = models.MultiLanguageBatchInput(documents=documents)

        # Construct URL
        url = self.sentiment.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self.config.endpoint", self.config.endpoint, 'str', skip_quote=True)
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        if model_version is not None:
            query_parameters['model-version'] = self._serialize.query("model_version", model_version, 'str')
        if show_stats is not None:
            query_parameters['showStats'] = self._serialize.query("show_stats", show_stats, 'bool')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if custom_headers:
            header_parameters.update(custom_headers)

        # Construct body
        body_content = self._serialize.body(input, 'MultiLanguageBatchInput')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.TextAnalyticsErrorException(self._deserialize, response)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('SentimentResponse', response)

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            return client_raw_response

        return deserialized
    sentiment.metadata = {'url': '/sentiment'}
