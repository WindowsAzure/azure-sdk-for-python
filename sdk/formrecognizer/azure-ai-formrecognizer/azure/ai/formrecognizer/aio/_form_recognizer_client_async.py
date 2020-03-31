# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

# pylint: disable=protected-access

from typing import (  # pylint: disable=unused-import
    Any,
    List,
    IO,
    TYPE_CHECKING,
)
import six
from azure.core.tracing.decorator_async import distributed_trace_async
from azure.core.polling.async_base_polling import AsyncLROBasePolling  # pylint: disable=no-name-in-module,import-error
from .._generated.aio._form_recognizer_client_async import FormRecognizerClient as FormRecognizer
from .._policies import CognitiveServicesCredentialPolicy
from .._response_handlers import (
    prepare_receipt_result,
    prepare_layout_result
)
from .._generated.models import AnalyzeOperationResult
from .._helpers import get_content_type, POLLING_INTERVAL
if TYPE_CHECKING:
    from .._credential import FormRecognizerApiKeyCredential
    from .._models import (
        ExtractedReceipt,
        ExtractedLayoutPage
    )


class FormRecognizerClient(object):
    """FormRecognizerClient.

    :param str endpoint: Supported Cognitive Services endpoints (protocol and hostname,
        for example: https://westus2.api.cognitive.microsoft.com).
    :param credential: Credentials needed for the client to connect to Azure.
        This is an instance of FormRecognizerApiKeyCredential if using an API key.
    :type credential: ~azure.ai.formrecognizer.FormRecognizerApiKeyCredential
    """

    def __init__(
            self,
            endpoint: str,
            credential: "FormRecognizerApiKeyCredential",
            **kwargs: Any
    ) -> None:
        self._client = FormRecognizer(
            endpoint=endpoint,
            credential=credential,
            authentication_policy=CognitiveServicesCredentialPolicy(credential),  # TODO: replace with core policy
            **kwargs
        )

    @distributed_trace_async
    async def begin_extract_receipts(self, stream: IO[bytes], **kwargs: Any) -> List["ExtractedReceipt"]:
        """Extract field text and semantic values from a given receipt document.
        The input document must be of one of the supported content types - 'application/pdf',
        'image/jpeg', 'image/png' or 'image/tiff'.

        :param stream: .pdf, .jpg, .png or .tiff type file stream.
        :type stream: stream
        :keyword bool include_text_details: Include text lines and element references in the result.
        :keyword str content_type: Media type of the body sent to the API.
        :return: LROPoller
        :rtype: ~azure.core.polling.LROPoller
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        if isinstance(stream, six.string_types):
            raise TypeError("Call begin_extract_receipts_from_url() to analyze a receipt from a url.")

        include_text_details = kwargs.pop("include_text_details", False)
        content_type = kwargs.pop("content_type", None)
        if content_type is None:
            content_type = get_content_type(stream)

        def callback(raw_response, _, headers):  # pylint: disable=unused-argument
            analyze_result = self._client._deserialize(AnalyzeOperationResult, raw_response)
            extracted_receipt = prepare_receipt_result(analyze_result, include_text_details)
            return extracted_receipt

        return await self._client.analyze_receipt_async(
            file_stream=stream,
            content_type=content_type,
            include_text_details=include_text_details,
            cls=kwargs.pop("cls", callback),
            polling=AsyncLROBasePolling(timeout=POLLING_INTERVAL, **kwargs),
            **kwargs
        )

    @distributed_trace_async
    async def begin_extract_receipts_from_url(self, url: str, **kwargs: Any) -> List["ExtractedReceipt"]:
        """Extract field text and semantic values from a given receipt document.
        The input document must be the location (Url) of the document to be analyzed.

        :param url: The url of the receipt.
        :type url: str
        :keyword bool include_text_details: Include text lines and element references in the result.
        :return: LROPoller
        :rtype: ~azure.core.polling.LROPoller
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        if not isinstance(url, six.string_types):
            raise TypeError("Call begin_extract_receipts() to analyze a receipt from a stream.")

        include_text_details = kwargs.pop("include_text_details", False)

        def callback(raw_response, _, headers):  # pylint: disable=unused-argument
            analyze_result = self._client._deserialize(AnalyzeOperationResult, raw_response)
            extracted_receipt = prepare_receipt_result(analyze_result, include_text_details)
            return extracted_receipt

        return await self._client.analyze_receipt_async(
            file_stream={"source": url},
            include_text_details=include_text_details,
            cls=kwargs.pop("cls", callback),
            polling=AsyncLROBasePolling(timeout=POLLING_INTERVAL, **kwargs),
            **kwargs
        )

    @distributed_trace_async
    async def begin_extract_layouts(self, stream: IO[bytes], **kwargs: Any) -> List["ExtractedLayoutPage"]:
        """Extract text and layout information from a given document.
        The input document must be of one of the supported content types - 'application/pdf',
        'image/jpeg', 'image/png' or 'image/tiff'.

        :param stream: .pdf, .jpg, .png or .tiff type file stream.
        :type stream: stream
        :keyword str content_type: Media type of the body sent to the API.
        :return: LROPoller
        :rtype: ~azure.core.polling.LROPoller
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        if isinstance(stream, six.string_types):
            raise TypeError("Call begin_extract_layouts_from_url() to analyze a document from a url.")

        content_type = kwargs.pop("content_type", None)
        if content_type is None:
            content_type = get_content_type(stream)

        def callback(raw_response, _, headers):  # pylint: disable=unused-argument
            analyze_result = self._client._deserialize(AnalyzeOperationResult, raw_response)
            extracted_layout = prepare_layout_result(analyze_result, include_elements=True)
            return extracted_layout

        return await self._client.analyze_layout_async(
            file_stream=stream,
            content_type=content_type,
            cls=kwargs.pop("cls", callback),
            polling=AsyncLROBasePolling(timeout=POLLING_INTERVAL, **kwargs),
            **kwargs
        )

    @distributed_trace_async
    async def begin_extract_layouts_from_url(self, url: str, **kwargs: Any) -> List["ExtractedLayoutPage"]:
        """Extract text and layout information from a given document.
        The input document must be the location (Url) of the document to be analyzed.

        :param url: The url of the document.
        :type url: str
        :return: LROPoller
        :rtype: ~azure.core.polling.LROPoller
        :raises: ~azure.core.exceptions.HttpResponseError
        """
        if not isinstance(url, six.string_types):
            raise TypeError("Call begin_extract_layouts() to analyze a document from a stream.")

        def callback(raw_response, _, headers):  # pylint: disable=unused-argument
            analyze_result = self._client._deserialize(AnalyzeOperationResult, raw_response)
            extracted_layout = prepare_layout_result(analyze_result, include_elements=True)
            return extracted_layout

        return await self._client.analyze_layout_async(
            file_stream={"source": url},
            cls=kwargs.pop("cls", callback),
            polling=AsyncLROBasePolling(timeout=POLLING_INTERVAL, **kwargs),
            **kwargs
        )

    async def __aenter__(self) -> "FormRecognizerClient":
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: "Any") -> None:
        await self._client.__aexit__(*args)

    async def close(self) -> None:
        """Close the :class:`~azure.ai.formrecognizer.FormRecognizerClient` session.
        """
        await self._client.__aexit__()
