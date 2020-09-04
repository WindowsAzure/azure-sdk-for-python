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
from msrest import Serializer, Deserializer
from typing import Any, Callable, Dict, Generic, List, Optional, TypeVar, Union
import warnings

from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError, map_error
from azure.core.pipeline import PipelineResponse
from azure.core.pipeline.transport import AsyncHttpResponse, HttpRequest


class TextAnalyticsClientOperationsMixin(object):

    async def entities_linking(
        self,
        documents: List["models.MultiLanguageInput"],
        model_version: Optional[str] = None,
        show_stats: Optional[bool] = None,
        **kwargs
    ) -> "models.EntityLinkingResult":
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
        api_version = self._get_api_version('entities_linking')
        if api_version == 'v3.0':
            from ..v3_0.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        elif api_version == 'v3.1-preview.1':
            from ..v3_1_preview_1.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        elif api_version == 'v3.1-preview.2':
            from ..v3_1_preview_2.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return await mixin_instance.entities_linking(documents, model_version, show_stats, **kwargs)

    async def entities_recognition_general(
        self,
        documents: List["models.MultiLanguageInput"],
        model_version: Optional[str] = None,
        show_stats: Optional[bool] = None,
        **kwargs
    ) -> "models.EntitiesResult":
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
        api_version = self._get_api_version('entities_recognition_general')
        if api_version == 'v3.0':
            from ..v3_0.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        elif api_version == 'v3.1-preview.1':
            from ..v3_1_preview_1.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        elif api_version == 'v3.1-preview.2':
            from ..v3_1_preview_2.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return await mixin_instance.entities_recognition_general(documents, model_version, show_stats, **kwargs)

    async def entities_recognition_pii(
        self,
        documents: List["models.MultiLanguageInput"],
        model_version: Optional[str] = None,
        show_stats: Optional[bool] = None,
        domain: Optional[str] = None,
        string_index_type: Optional[Union[str, "models.StringIndexType"]] = "TextElements_v8",
        **kwargs
    ) -> "models.PiiEntitiesResult":
        """Entities containing personal information.

        The API returns a list of entities with personal information (\"SSN\", \"Bank Account\" etc) in
        the document. For the list of supported entity types, check :code:`<a
        href="https://aka.ms/tanerpii">Supported Entity Types in Text Analytics API</a>`. See the
        :code:`<a href="https://aka.ms/talangs">Supported languages in Text Analytics API</a>` for the
        list of enabled languages.

        :param documents: The set of documents to process as part of this batch.
        :type documents: list[~azure.ai.textanalytics.v3_1_preview_2.models.MultiLanguageInput]
        :param model_version: (Optional) This value indicates which model will be used for scoring. If
         a model-version is not specified, the API should default to the latest, non-preview version.
        :type model_version: str
        :param show_stats: (Optional) if set to true, response will contain request and document level
         statistics.
        :type show_stats: bool
        :param domain: (Optional) if set to 'PHI', response will contain only PHI entities.
        :type domain: str
        :param string_index_type: (Optional) Specifies the method used to interpret string offsets.
         Defaults to Text Elements (Graphemes) according to Unicode v8.0.0. For additional information
         see https://aka.ms/text-analytics-offsets.
        :type string_index_type: str or ~azure.ai.textanalytics.v3_1_preview_2.models.StringIndexType
        :keyword callable cls: A custom type or function that will be passed the direct response
        :return: PiiEntitiesResult, or the result of cls(response)
        :rtype: ~azure.ai.textanalytics.v3_1_preview_2.models.PiiEntitiesResult
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        api_version = self._get_api_version('entities_recognition_pii')
        if api_version == 'v3.1-preview.1':
            from ..v3_1_preview_1.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        elif api_version == 'v3.1-preview.2':
            from ..v3_1_preview_2.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return await mixin_instance.entities_recognition_pii(documents, model_version, show_stats, domain, string_index_type, **kwargs)

    async def key_phrases(
        self,
        documents: List["models.MultiLanguageInput"],
        model_version: Optional[str] = None,
        show_stats: Optional[bool] = None,
        **kwargs
    ) -> "models.KeyPhraseResult":
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
        api_version = self._get_api_version('key_phrases')
        if api_version == 'v3.0':
            from ..v3_0.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        elif api_version == 'v3.1-preview.1':
            from ..v3_1_preview_1.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        elif api_version == 'v3.1-preview.2':
            from ..v3_1_preview_2.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return await mixin_instance.key_phrases(documents, model_version, show_stats, **kwargs)

    async def languages(
        self,
        documents: List["models.LanguageInput"],
        model_version: Optional[str] = None,
        show_stats: Optional[bool] = None,
        **kwargs
    ) -> "models.LanguageResult":
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
        api_version = self._get_api_version('languages')
        if api_version == 'v3.0':
            from ..v3_0.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        elif api_version == 'v3.1-preview.1':
            from ..v3_1_preview_1.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        elif api_version == 'v3.1-preview.2':
            from ..v3_1_preview_2.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return await mixin_instance.languages(documents, model_version, show_stats, **kwargs)

    async def sentiment(
        self,
        documents: List["models.MultiLanguageInput"],
        model_version: Optional[str] = None,
        show_stats: Optional[bool] = None,
        **kwargs
    ) -> "models.SentimentResponse":
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
        api_version = self._get_api_version('sentiment')
        if api_version == 'v3.0':
            from ..v3_0.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        elif api_version == 'v3.1-preview.1':
            from ..v3_1_preview_1.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        elif api_version == 'v3.1-preview.2':
            from ..v3_1_preview_2.aio.operations_async import TextAnalyticsClientOperationsMixin as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        mixin_instance = OperationClass()
        mixin_instance._client = self._client
        mixin_instance._config = self._config
        mixin_instance._serialize = Serializer(self._models_dict(api_version))
        mixin_instance._deserialize = Deserializer(self._models_dict(api_version))
        return await mixin_instance.sentiment(documents, model_version, show_stats, **kwargs)
