# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from typing import Any, Callable, Dict, Generic, List, Optional, TypeVar
import warnings

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest

from ... import models as _models

T = TypeVar('T')
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]

class TextAnalyticsClientOperationsMixin:

    async def entities_recognition_general(
        self,
        documents: List["_models.MultiLanguageInput"],
        model_version: Optional[str] = None,
        show_stats: Optional[bool] = None,
        **kwargs
    ) -> "_models.EntitiesResult":
        """Named Entity Recognition.

        The API returns a list of general named entities in a given document. For the list of supported
        entity types, check :code:`<a href="https://aka.ms/taner">Supported Entity Types in Text
        Analytics API</a>`. See the :code:`<a href="https://aka.ms/talangs">Supported languages in Text
        Analytics API</a>` for the list of enabled languages.

        :param documents: The set of documents to process as part of this batch.
        :type documents: list[~azure.ai.textanalytics.v3_0.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will be used for scoring. If
         a model-version is not specified, the API should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain input and document level
         statistics.
        :type show_stats: bool
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: EntitiesResult, or the result of cls(response)
        :rtype: ~azure.ai.textanalytics.v3_0.models.EntitiesResult
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.EntitiesResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        _input = _models.MultiLanguageBatchInput(documents=documents)
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json, text/json"

        # Construct URL
        url = self.entities_recognition_general.metadata['url']  # type: ignore
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if model_version is not None:
            query_parameters['model-version'] = self._serialize.query("model_version", model_version, 'str')
        if show_stats is not None:
            query_parameters['showStats'] = self._serialize.query("show_stats", show_stats, 'bool')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(_input, 'MultiLanguageBatchInput')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('EntitiesResult', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    entities_recognition_general.metadata = {'url': '/entities/recognition/general'}  # type: ignore

    async def entities_linking(
        self,
        documents: List["_models.MultiLanguageInput"],
        model_version: Optional[str] = None,
        show_stats: Optional[bool] = None,
        **kwargs
    ) -> "_models.EntityLinkingResult":
        """Linked entities from a well-known knowledge base.

        The API returns a list of recognized entities with links to a well-known knowledge base. See
        the :code:`<a href="https://aka.ms/talangs">Supported languages in Text Analytics API</a>` for
        the list of enabled languages.

        :param documents: The set of documents to process as part of this batch.
        :type documents: list[~azure.ai.textanalytics.v3_0.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will be used for scoring. If
         a model-version is not specified, the API should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain input and document level
         statistics.
        :type show_stats: bool
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: EntityLinkingResult, or the result of cls(response)
        :rtype: ~azure.ai.textanalytics.v3_0.models.EntityLinkingResult
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.EntityLinkingResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        _input = _models.MultiLanguageBatchInput(documents=documents)
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json, text/json"

        # Construct URL
        url = self.entities_linking.metadata['url']  # type: ignore
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if model_version is not None:
            query_parameters['model-version'] = self._serialize.query("model_version", model_version, 'str')
        if show_stats is not None:
            query_parameters['showStats'] = self._serialize.query("show_stats", show_stats, 'bool')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(_input, 'MultiLanguageBatchInput')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('EntityLinkingResult', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    entities_linking.metadata = {'url': '/entities/linking'}  # type: ignore

    async def key_phrases(
        self,
        documents: List["_models.MultiLanguageInput"],
        model_version: Optional[str] = None,
        show_stats: Optional[bool] = None,
        **kwargs
    ) -> "_models.KeyPhraseResult":
        """Key Phrases.

        The API returns a list of strings denoting the key phrases in the input text. See the :code:`<a
        href="https://aka.ms/talangs">Supported languages in Text Analytics API</a>` for the list of
        enabled languages.

        :param documents: The set of documents to process as part of this batch.
        :type documents: list[~azure.ai.textanalytics.v3_0.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will be used for scoring. If
         a model-version is not specified, the API should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain input and document level
         statistics.
        :type show_stats: bool
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: KeyPhraseResult, or the result of cls(response)
        :rtype: ~azure.ai.textanalytics.v3_0.models.KeyPhraseResult
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.KeyPhraseResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        _input = _models.MultiLanguageBatchInput(documents=documents)
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json, text/json"

        # Construct URL
        url = self.key_phrases.metadata['url']  # type: ignore
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if model_version is not None:
            query_parameters['model-version'] = self._serialize.query("model_version", model_version, 'str')
        if show_stats is not None:
            query_parameters['showStats'] = self._serialize.query("show_stats", show_stats, 'bool')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(_input, 'MultiLanguageBatchInput')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('KeyPhraseResult', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    key_phrases.metadata = {'url': '/keyPhrases'}  # type: ignore

    async def languages(
        self,
        documents: List["_models.LanguageInput"],
        model_version: Optional[str] = None,
        show_stats: Optional[bool] = None,
        **kwargs
    ) -> "_models.LanguageResult":
        """Detect Language.

        The API returns the detected language and a numeric score between 0 and 1. Scores close to 1
        indicate 100% certainty that the identified language is true. See the :code:`<a
        href="https://aka.ms/talangs">Supported languages in Text Analytics API</a>` for the list of
        enabled languages.

        :param documents:
        :type documents: list[~azure.ai.textanalytics.v3_0.models.LanguageInput]
        :param model_version: (Optional) This value indicates which model will be used for scoring. If
         a model-version is not specified, the API should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain input and document level
         statistics.
        :type show_stats: bool
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: LanguageResult, or the result of cls(response)
        :rtype: ~azure.ai.textanalytics.v3_0.models.LanguageResult
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.LanguageResult"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        _input = _models.LanguageBatchInput(documents=documents)
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json, text/json"

        # Construct URL
        url = self.languages.metadata['url']  # type: ignore
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if model_version is not None:
            query_parameters['model-version'] = self._serialize.query("model_version", model_version, 'str')
        if show_stats is not None:
            query_parameters['showStats'] = self._serialize.query("show_stats", show_stats, 'bool')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(_input, 'LanguageBatchInput')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('LanguageResult', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    languages.metadata = {'url': '/languages'}  # type: ignore

    async def sentiment(
        self,
        documents: List["_models.MultiLanguageInput"],
        model_version: Optional[str] = None,
        show_stats: Optional[bool] = None,
        **kwargs
    ) -> "_models.SentimentResponse":
        """Sentiment.

        The API returns a sentiment prediction, as well as sentiment scores for each sentiment class
        (Positive, Negative, and Neutral) for the document and each sentence within it. See the
        :code:`<a href="https://aka.ms/talangs">Supported languages in Text Analytics API</a>` for the
        list of enabled languages.

        :param documents: The set of documents to process as part of this batch.
        :type documents: list[~azure.ai.textanalytics.v3_0.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will be used for scoring. If
         a model-version is not specified, the API should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain input and document level
         statistics.
        :type show_stats: bool
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: SentimentResponse, or the result of cls(response)
        :rtype: ~azure.ai.textanalytics.v3_0.models.SentimentResponse
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        cls = kwargs.pop('cls', None)  # type: ClsType["_models.SentimentResponse"]
        error_map = {
            401: ClientAuthenticationError, 404: ResourceNotFoundError, 409: ResourceExistsError
        }
        error_map.update(kwargs.pop('error_map', {}))

        _input = _models.MultiLanguageBatchInput(documents=documents)
        content_type = kwargs.pop("content_type", "application/json")
        accept = "application/json, text/json"

        # Construct URL
        url = self.sentiment.metadata['url']  # type: ignore
        path_format_arguments = {
            'Endpoint': self._serialize.url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}  # type: Dict[str, Any]
        if model_version is not None:
            query_parameters['model-version'] = self._serialize.query("model_version", model_version, 'str')
        if show_stats is not None:
            query_parameters['showStats'] = self._serialize.query("show_stats", show_stats, 'bool')

        # Construct headers
        header_parameters = {}  # type: Dict[str, Any]
        header_parameters['Content-Type'] = self._serialize.header("content_type", content_type, 'str')
        header_parameters['Accept'] = self._serialize.header("accept", accept, 'str')

        body_content_kwargs = {}  # type: Dict[str, Any]
        body_content = self._serialize.body(_input, 'MultiLanguageBatchInput')
        body_content_kwargs['content'] = body_content
        request = self._client.post(url, query_parameters, header_parameters, **body_content_kwargs)
        pipeline_response = await self._client._pipeline.run(request, stream=False, **kwargs)
        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            error = self._deserialize.failsafe_deserialize(_models.ErrorResponse, response)
            raise HttpResponseError(response=response, model=error)

        deserialized = self._deserialize('SentimentResponse', pipeline_response)

        if cls:
            return cls(pipeline_response, deserialized, {})

        return deserialized
    sentiment.metadata = {'url': '/sentiment'}  # type: ignore
