# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import TYPE_CHECKING

from azure.core import PipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any

    from azure.core.credentials import TokenCredential

from ._configuration import TextAnalyticsClientConfiguration
from .operations import TextAnalyticsClientOperationsMixin
from . import models


class TextAnalyticsClient(TextAnalyticsClientOperationsMixin):
    """The Text Analytics API is a suite of text analytics web services built with best-in-class Microsoft machine learning algorithms. The API can be used to analyze unstructured text for tasks such as sentiment analysis, key phrase extraction and language detection. No training data is needed to use this API; just bring your text data. This API uses advanced natural language processing techniques to deliver best in class predictions. Further documentation can be found in https://docs.microsoft.com/en-us/azure/cognitive-services/text-analytics/overview.

    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param endpoint: Supported Cognitive Services endpoints (protocol and hostname, for example: https://westus.api.cognitive.microsoft.com).
    :type endpoint: str
    """

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        endpoint,  # type: str
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        base_url = '{Endpoint}/text/analytics/v3.1-preview.1'
        self._config = TextAnalyticsClientConfiguration(credential, endpoint, **kwargs)
        self._client = PipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)


    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> TextAnalyticsClient
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
