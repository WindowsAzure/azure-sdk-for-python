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

from azure.core.exceptions import map_error
from ... import models
import uuid


class TextAnalyticsClientOperationsMixin:

    async def entities_recognition_general(self, documents, model_version=None, show_stats=None, *, cls=None, **kwargs):
        """Named Entity Recognition.

        The API returns a list of general named entities in a given document.
        For the list of supported entity types, check <a
        href="https://aka.ms/taner">Supported Entity Types in Text Analytics
        API</a>. See the <a href="https://aka.ms/talangs">Supported languages
        in Text Analytics API</a> for the list of enabled languages.

        :param documents: The set of documents to process as part of this
         batch.
        :type documents:
         list[~azure.ai.textanalytics.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will
         be used for scoring. If a model-version is not specified, the API
         should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain
         input and document level statistics.
        :type show_stats: bool
        :param callable cls: A custom type or function that will be passed the
         direct response
        :return: EntitiesResult or the result of cls(response)
        :rtype: ~azure.ai.textanalytics.models.EntitiesResult
        :raises:
         :class:`TextAnalyticsErrorException<azure.ai.textanalytics.models.TextAnalyticsErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        input = models.MultiLanguageBatchInput(documents=documents)

        # Construct URL
        url = self.entities_recognition_general.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True)
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
        if self._config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())

        # Construct body
        body_content = self._serialize.body(input, 'MultiLanguageBatchInput')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.TextAnalyticsErrorException(response, self._deserialize)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('EntitiesResult', response)

        if cls:
            return cls(response, deserialized, None)

        return deserialized
    entities_recognition_general.metadata = {'url': '/entities/recognition/general'}

    async def entities_linking(self, documents, model_version=None, show_stats=None, *, cls=None, **kwargs):
        """Linked entities from a well-known knowledge base.

        The API returns a list of recognized entities with links to a
        well-known knowledge base. See the <a
        href="https://aka.ms/talangs">Supported languages in Text Analytics
        API</a> for the list of enabled languages.

        :param documents: The set of documents to process as part of this
         batch.
        :type documents:
         list[~azure.ai.textanalytics.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will
         be used for scoring. If a model-version is not specified, the API
         should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain
         input and document level statistics.
        :type show_stats: bool
        :param callable cls: A custom type or function that will be passed the
         direct response
        :return: EntityLinkingResult or the result of cls(response)
        :rtype: ~azure.ai.textanalytics.models.EntityLinkingResult
        :raises:
         :class:`TextAnalyticsErrorException<azure.ai.textanalytics.models.TextAnalyticsErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        input = models.MultiLanguageBatchInput(documents=documents)

        # Construct URL
        url = self.entities_linking.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True)
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
        if self._config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())

        # Construct body
        body_content = self._serialize.body(input, 'MultiLanguageBatchInput')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.TextAnalyticsErrorException(response, self._deserialize)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('EntityLinkingResult', response)

        if cls:
            return cls(response, deserialized, None)

        return deserialized
    entities_linking.metadata = {'url': '/entities/linking'}

    async def key_phrases(self, documents, model_version=None, show_stats=None, *, cls=None, **kwargs):
        """Key Phrases.

        The API returns a list of strings denoting the key phrases in the input
        text. See the <a href="https://aka.ms/talangs">Supported languages in
        Text Analytics API</a> for the list of enabled languages.

        :param documents: The set of documents to process as part of this
         batch.
        :type documents:
         list[~azure.ai.textanalytics.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will
         be used for scoring. If a model-version is not specified, the API
         should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain
         input and document level statistics.
        :type show_stats: bool
        :param callable cls: A custom type or function that will be passed the
         direct response
        :return: KeyPhraseResult or the result of cls(response)
        :rtype: ~azure.ai.textanalytics.models.KeyPhraseResult
        :raises:
         :class:`TextAnalyticsErrorException<azure.ai.textanalytics.models.TextAnalyticsErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        input = models.MultiLanguageBatchInput(documents=documents)

        # Construct URL
        url = self.key_phrases.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True)
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
        if self._config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())

        # Construct body
        body_content = self._serialize.body(input, 'MultiLanguageBatchInput')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.TextAnalyticsErrorException(response, self._deserialize)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('KeyPhraseResult', response)

        if cls:
            return cls(response, deserialized, None)

        return deserialized
    key_phrases.metadata = {'url': '/keyPhrases'}

    async def languages(self, documents, model_version=None, show_stats=None, *, cls=None, **kwargs):
        """Detect Language.

        The API returns the detected language and a numeric score between 0 and
        1. Scores close to 1 indicate 100% certainty that the identified
        language is true. See the <a href="https://aka.ms/talangs">Supported
        languages in Text Analytics API</a> for the list of enabled languages.

        :param documents:
        :type documents: list[~azure.ai.textanalytics.models.LanguageInput]
        :param model_version: (Optional) This value indicates which model will
         be used for scoring. If a model-version is not specified, the API
         should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain
         input and document level statistics.
        :type show_stats: bool
        :param callable cls: A custom type or function that will be passed the
         direct response
        :return: LanguageResult or the result of cls(response)
        :rtype: ~azure.ai.textanalytics.models.LanguageResult
        :raises:
         :class:`TextAnalyticsErrorException<azure.ai.textanalytics.models.TextAnalyticsErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        input = models.LanguageBatchInput(documents=documents)

        # Construct URL
        url = self.languages.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True)
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
        if self._config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())

        # Construct body
        body_content = self._serialize.body(input, 'LanguageBatchInput')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.TextAnalyticsErrorException(response, self._deserialize)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('LanguageResult', response)

        if cls:
            return cls(response, deserialized, None)

        return deserialized
    languages.metadata = {'url': '/languages'}

    async def sentiment(self, documents, model_version=None, show_stats=None, *, cls=None, **kwargs):
        """Sentiment.

        The API returns a sentiment prediction, as well as sentiment scores for
        each sentiment class (Positive, Negative, and Neutral) for the document
        and each sentence within it. See the <a
        href="https://aka.ms/talangs">Supported languages in Text Analytics
        API</a> for the list of enabled languages.

        :param documents: The set of documents to process as part of this
         batch.
        :type documents:
         list[~azure.ai.textanalytics.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will
         be used for scoring. If a model-version is not specified, the API
         should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain
         input and document level statistics.
        :type show_stats: bool
        :param callable cls: A custom type or function that will be passed the
         direct response
        :return: SentimentResponse or the result of cls(response)
        :rtype: ~azure.ai.textanalytics.models.SentimentResponse
        :raises:
         :class:`TextAnalyticsErrorException<azure.ai.textanalytics.models.TextAnalyticsErrorException>`
        """
        error_map = kwargs.pop('error_map', None)
        input = models.MultiLanguageBatchInput(documents=documents)

        # Construct URL
        url = self.sentiment.metadata['url']
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True)
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
        if self._config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())

        # Construct body
        body_content = self._serialize.body(input, 'MultiLanguageBatchInput')

        # Construct and send request
        request = self._client.post(url, query_parameters, header_parameters, body_content)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise models.TextAnalyticsErrorException(response, self._deserialize)

        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('SentimentResponse', response)

        if cls:
            return cls(response, deserialized, None)

        return deserialized
    sentiment.metadata = {'url': '/sentiment'}
