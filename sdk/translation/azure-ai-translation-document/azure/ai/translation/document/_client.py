# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

from typing import Any, TYPE_CHECKING, List, Union
from azure.core.tracing.decorator import distributed_trace
from azure.core.polling import LROPoller
from azure.core.polling.base_polling import LROBasePolling
from ._generated import BatchDocumentTranslationClient as _BatchDocumentTranslationClient
from ._generated.models import TranslationStatus as _TranslationStatus
from ._models import (
    JobStatusResult,
    DocumentStatusResult,
    DocumentTranslationInput,
    FileFormat
)
from ._user_agent import USER_AGENT
from ._polling import TranslationPolling
from ._helpers import get_http_logging_policy, convert_datetime, get_authentication_policy
if TYPE_CHECKING:
    from azure.core.paging import ItemPaged
    from azure.core.credentials import TokenCredential, AzureKeyCredential


class DocumentTranslationClient(object):  # pylint: disable=r0205

    def __init__(self, endpoint, credential, **kwargs):
        # type: (str, Union[AzureKeyCredential, TokenCredential], Any) -> None
        """DocumentTranslationClient is your interface to the Document Translation service.
        Use the client to translate whole documents while preserving source document
        structure and text formatting.

        :param str endpoint: Supported Document Translation endpoint (protocol and hostname, for example:
            https://<resource-name>.cognitiveservices.azure.com/).
        :param credential: Credentials needed for the client to connect to Azure.
            This is an instance of AzureKeyCredential if using an API key or a token
            credential from :mod:`azure.identity`.
        :type credential: :class:`~azure.core.credentials.AzureKeyCredential` or
            :class:`~azure.core.credentials.TokenCredential`
        :keyword api_version:
            The API version of the service to use for requests. It defaults to the latest service version.
            Setting to an older version may result in reduced feature compatibility.
        :paramtype api_version: str or ~azure.ai.translation.document.DocumentTranslationApiVersion

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_authentication.py
                :start-after: [START create_dt_client_with_key]
                :end-before: [END create_dt_client_with_key]
                :language: python
                :dedent: 4
                :caption: Creating the DocumentTranslationClient with an endpoint and API key.

            .. literalinclude:: ../samples/sample_authentication.py
                :start-after: [START create_dt_client_with_aad]
                :end-before: [END create_dt_client_with_aad]
                :language: python
                :dedent: 4
                :caption: Creating the DocumentTranslationClient with a token credential.
        """
        self._endpoint = endpoint
        self._credential = credential
        self._api_version = kwargs.pop('api_version', None)

        authentication_policy = get_authentication_policy(credential)

        self._client = _BatchDocumentTranslationClient(
            endpoint=endpoint,
            credential=credential,  # type: ignore
            api_version=self._api_version,
            sdk_moniker=USER_AGENT,
            authentication_policy=authentication_policy,
            http_logging_policy=get_http_logging_policy(),
            **kwargs
        )

    def __enter__(self):
        # type: () -> DocumentTranslationClient
        self._client.__enter__()  # pylint:disable=no-member
        return self

    def __exit__(self, *args):
        # type: (*Any) -> None
        self._client.__exit__(*args)  # pylint:disable=no-member

    def close(self):
        # type: () -> None
        """Close the :class:`~azure.ai.translation.document.DocumentTranslationClient` session."""
        return self._client.close()

    @distributed_trace
    def create_translation_job(self, inputs, **kwargs):
        # type: (List[DocumentTranslationInput], **Any) -> JobStatusResult
        """Create a document translation job which translates the document(s) in your source container
        to your TranslationTarget(s) in the given language.

        For supported languages and document formats, see the service documentation:
        https://docs.microsoft.com/azure/cognitive-services/translator/document-translation/overview

        :param inputs: A list of translation inputs. Each individual input has a single
            source URL to documents and can contain multiple TranslationTargets (one for each language)
            for the destination to write translated documents.
        :type inputs: List[~azure.ai.translation.document.DocumentTranslationInput]
        :return: A JobStatusResult with information on the status of the translation job.
        :rtype: ~azure.ai.translation.document.JobStatusResult
        :raises ~azure.core.exceptions.HttpResponseError:

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_check_document_statuses.py
                :start-after: [START create_translation_job]
                :end-before: [END create_translation_job]
                :language: python
                :dedent: 4
                :caption: Create a translation job.
        """

        # submit translation job
        response_headers = self._client.document_translation._start_translation_initial(  # pylint: disable=protected-access
            inputs=DocumentTranslationInput._to_generated_list(inputs),  # pylint: disable=protected-access
            cls=lambda pipeline_response, _, response_headers: response_headers,
            **kwargs
        )

        def get_job_id(response_headers):
            operation_loc_header = response_headers['Operation-Location']
            return operation_loc_header.split('/')[-1]

        # get job id from response header
        job_id = get_job_id(response_headers)

        # get job status
        return self.get_job_status(job_id)


    @distributed_trace
    def get_job_status(self, job_id, **kwargs):
        # type: (str, **Any) -> JobStatusResult
        """Gets the status of a translation job.

        The status includes the overall job status, as well as a summary of
        the documents that are being translated as part of that translation job.

        :param str job_id: The translation job ID.
        :return: A JobStatusResult with information on the status of the translation job.
        :rtype: ~azure.ai.translation.document.JobStatusResult
        :raises ~azure.core.exceptions.HttpResponseError or ~azure.core.exceptions.ResourceNotFoundError:
        """

        job_status = self._client.document_translation.get_translation_status(job_id, **kwargs)
        return JobStatusResult._from_generated(job_status)  # pylint: disable=protected-access

    @distributed_trace
    def cancel_job(self, job_id, **kwargs):
        # type: (str, **Any) -> None
        """Cancel a currently processing or queued job.

        A job will not be cancelled if it is already completed, failed, or cancelling.
        All documents that have completed translation will not be cancelled and will be charged.
        If possible, all pending documents will be cancelled.

        :param str job_id: The translation job ID.
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError or ~azure.core.exceptions.ResourceNotFoundError:
        """

        self._client.document_translation.cancel_translation(job_id, **kwargs)

    @distributed_trace
    def wait_until_done(self, job_id, **kwargs):
        # type: (str, **Any) -> JobStatusResult
        """Wait until the translation job is done.

        A job is considered "done" when it reaches a terminal state like
        Succeeded, Failed, Cancelled.

        :param str job_id: The translation job ID.
        :return: A JobStatusResult with information on the status of the translation job.
        :rtype: ~azure.ai.translation.document.JobStatusResult
        :raises ~azure.core.exceptions.HttpResponseError or ~azure.core.exceptions.ResourceNotFoundError:
            Will raise if validation fails on the input. E.g. insufficient permissions on the blob containers.

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_create_translation_job.py
                :start-after: [START wait_until_done]
                :end-before: [END wait_until_done]
                :language: python
                :dedent: 4
                :caption: Create a translation job and wait until it is done.
        """

        pipeline_response = self._client.document_translation.get_translation_status(
            job_id,
            cls=lambda pipeline_response, _, response_headers: pipeline_response
        )

        def callback(raw_response):
            detail = self._client._deserialize(_TranslationStatus, raw_response)  # pylint: disable=protected-access
            return JobStatusResult._from_generated(detail)  # pylint: disable=protected-access

        poller = LROPoller(
            client=self._client._client,  # pylint: disable=protected-access
            initial_response=pipeline_response,
            deserialization_callback=callback,
            polling_method=LROBasePolling(
                timeout=self._client._config.polling_interval,  # pylint: disable=protected-access
                lro_algorithms=[TranslationPolling()],
                **kwargs
            ),
        )
        return poller.result()

    @distributed_trace
    def list_submitted_jobs(self, **kwargs):
        # type: (**Any) -> ItemPaged[JobStatusResult]
        """List all the submitted translation jobs under the Document Translation resource.

        :keyword int top: the total number of jobs to return (across all pages) from all submitted jobs.
        :keyword int skip: the number of jobs to skip (from beginning of the all submitted jobs).
            By default, we sort by all submitted jobs descendingly by start time.
        :keyword int results_per_page: is the number of jobs returned per page.
        :keyword list[str] job_ids: job ids to filter by.
        :keyword list[str] statuses: job statuses to filter by.
        :keyword Union[str, datetime.datetime] created_after: get jobs created after certain datetime.
        :keyword Union[str, datetime.datetime] created_before: get jobs created before certain datetime.
        :keyword list[str] order_by: the sorting query for the jobs returned.
            format: ["parm1 asc/desc", "parm2 asc/desc", ...]
            (ex: 'createdDateTimeUtc asc', 'createdDateTimeUtc desc').
        :return: ~azure.core.paging.ItemPaged[:class:`~azure.ai.translation.document.JobStatusResult`]
        :rtype: ~azure.core.paging.ItemPaged
        :raises ~azure.core.exceptions.HttpResponseError:

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_list_all_submitted_jobs.py
                :start-after: [START list_all_jobs]
                :end-before: [END list_all_jobs]
                :language: python
                :dedent: 4
                :caption: List all submitted jobs under the resource.
        """
        created_after = kwargs.pop("created_after", None)
        created_before = kwargs.pop("created_before", None)
        created_after = convert_datetime(created_after) if created_after else None
        created_before = convert_datetime(created_before) if created_before else None
        results_per_page = kwargs.pop("results_per_page", None)
        job_ids = kwargs.pop("job_ids", None)

        def _convert_from_generated_model(generated_model):  # pylint: disable=protected-access
            return JobStatusResult._from_generated(generated_model)  # pylint: disable=protected-access

        model_conversion_function = kwargs.pop(
            "cls",
            lambda job_statuses: [
                _convert_from_generated_model(job_status) for job_status in job_statuses
            ])

        return self._client.document_translation.get_translations_status(
            cls=model_conversion_function,
            maxpagesize=results_per_page,
            created_date_time_utc_start=created_after,
            created_date_time_utc_end=created_before,
            ids=job_ids,
            **kwargs
        )

    @distributed_trace
    def list_all_document_statuses(self, job_id, **kwargs):
        # type: (str, **Any) -> ItemPaged[DocumentStatusResult]
        """List all the document statuses for a given translation job.

        :param str job_id: ID of translation job to list documents for.
        :keyword int top: the total number of documents to return (across all pages).
        :keyword int skip: the number of documents to skip (from beginning).
            By default, we sort by all documents descendingly by start time.
        :keyword int results_per_page: is the number of documents returned per page.
        :keyword list[str] document_ids: document IDs to filter by.
        :keyword list[str] statuses: document statuses to filter by.
        :keyword Union[str, datetime.datetime] translated_after: get document translated after certain datetime.
        :keyword Union[str, datetime.datetime] translated_before: get document translated before certain datetime.
        :keyword list[str] order_by: the sorting query for the documents.
            format: ["parm1 asc/desc", "parm2 asc/desc", ...]
            (ex: 'createdDateTimeUtc asc', 'createdDateTimeUtc desc').
        :return: ~azure.core.paging.ItemPaged[:class:`~azure.ai.translation.document.DocumentStatusResult`]
        :rtype: ~azure.core.paging.ItemPaged
        :raises ~azure.core.exceptions.HttpResponseError:

        .. admonition:: Example:

            .. literalinclude:: ../samples/sample_create_translation_job.py
                :start-after: [START list_all_document_statuses]
                :end-before: [END list_all_document_statuses]
                :language: python
                :dedent: 4
                :caption: List all the document statuses under the translation job.
        """
        translated_after = kwargs.pop("translated_after", None)
        translated_before = kwargs.pop("translated_before", None)
        translated_after = convert_datetime(translated_after) if translated_after else None
        translated_before = convert_datetime(translated_before) if translated_before else None
        results_per_page = kwargs.pop("results_per_page", None)
        document_ids = kwargs.pop("document_ids", None)


        def _convert_from_generated_model(generated_model):
            return DocumentStatusResult._from_generated(generated_model)  # pylint: disable=protected-access

        model_conversion_function = kwargs.pop(
            "cls",
            lambda doc_statuses: [
                _convert_from_generated_model(doc_status) for doc_status in doc_statuses
            ])

        return self._client.document_translation.get_documents_status(
            id=job_id,
            cls=model_conversion_function,
            maxpagesize=results_per_page,
            created_date_time_utc_start=translated_after,
            created_date_time_utc_end=translated_before,
            ids=document_ids,
            **kwargs
        )

    @distributed_trace
    def get_document_status(self, job_id, document_id, **kwargs):
        # type: (str, str, **Any) -> DocumentStatusResult
        """Get the status of an individual document within a translation job.

        :param str job_id: The translation job ID.
        :param str document_id: The ID for the document.
        :return: A DocumentStatusResult with information on the status of the document.
        :rtype: ~azure.ai.translation.document.DocumentStatusResult
        :raises ~azure.core.exceptions.HttpResponseError or ~azure.core.exceptions.ResourceNotFoundError:
        """

        document_status = self._client.document_translation.get_document_status(
            job_id,
            document_id,
            **kwargs)
        return DocumentStatusResult._from_generated(document_status)  # pylint: disable=protected-access

    @distributed_trace
    def get_glossary_formats(self, **kwargs):
        # type: (**Any) -> List[FileFormat]
        """Get the list of the glossary formats supported by the Document Translation service.

        :return: A list of supported glossary formats.
        :rtype: List[FileFormat]
        :raises ~azure.core.exceptions.HttpResponseError:
        """

        glossary_formats = self._client.document_translation.get_supported_glossary_formats(**kwargs)
        return FileFormat._from_generated_list(glossary_formats.value)  # pylint: disable=protected-access

    @distributed_trace
    def get_document_formats(self, **kwargs):
        # type: (**Any) -> List[FileFormat]
        """Get the list of the document formats supported by the Document Translation service.

        :return: A list of supported document formats for translation.
        :rtype: List[FileFormat]
        :raises ~azure.core.exceptions.HttpResponseError:
        """

        document_formats = self._client.document_translation.get_supported_document_formats(**kwargs)
        return FileFormat._from_generated_list(document_formats.value)  # pylint: disable=protected-access
