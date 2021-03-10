# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Any, TYPE_CHECKING, Union

from azure.core import PipelineClient
from msrest import Serializer

from azure.core.credentials import AzureKeyCredential
from azure.core.protocol import HttpRequest, HttpResponse

from ._configuration import TextAnalyticsClientConfiguration

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential


class TextAnalyticsClient:
    """The Text Analytics API is a suite of text analytics web services built with best-in-class Microsoft machine learning algorithms. The API can be used to analyze unstructured text for tasks such as sentiment analysis, key phrase extraction and language detection. No training data is needed to use this API; just bring your text data. This API uses advanced natural language processing techniques to deliver best in class predictions. Further documentation can be found in https://docs.microsoft.com/en-us/azure/cognitive-services/text-analytics/overview.

    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential or ~azure.core.credentials.AzureKeyCredential
    :param endpoint: Supported Cognitive Services endpoints (protocol and hostname, for example: https://westus.api.cognitive.microsoft.com).
    :type endpoint: str
    """

    def __init__(
        self,
        credential: Union["TokenCredential", AzureKeyCredential],
        endpoint: str,
        **kwargs: Any
    ) -> None:
        base_url = '{Endpoint}'
        self._config = TextAnalyticsClientConfiguration(credential, endpoint, **kwargs)
        self._client: PipelineClient = PipelineClient(base_url=base_url, config=self._config, **kwargs)


    def send_request(self, http_request: HttpRequest, **kwargs: Any) -> HttpResponse:
        """Runs the network request through the client's chained policies.

        :param http_request: The network request you want to make. Required.
        :type http_request: ~azure.core.protocol.HttpRequest
        :keyword bool stream_response: Whether the response payload will be streamed. Defaults to False.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.protocol.HttpResponse
        """
        path_format_arguments = {
            'Endpoint': Serializer().url("self._config.endpoint", self._config.endpoint, 'str', skip_quote=True),
        }
        http_request.url = self._client.format_url(http_request.url, **path_format_arguments)
        stream_response = kwargs.pop("stream_response", False)
        pipeline_response = self._client._pipeline.run(http_request._http_request, stream=stream_response, **kwargs)
        return pipeline_response.http_response._to_protocol()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "TextAnalyticsClient":
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details: Any) -> None:
        self._client.__exit__(*exc_details)
