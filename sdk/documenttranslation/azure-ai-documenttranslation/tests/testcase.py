# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

import os
import time
import datetime
import uuid
from devtools_testutils import (
    AzureTestCase,
)
from azure_devtools.scenario_tests import (
    RecordingProcessor,
    ReplayableTest
)
from azure.storage.blob import generate_container_sas, ContainerClient
from azure.ai.documenttranslation import DocumentTranslationInput, TranslationTarget


class OperationLocationReplacer(RecordingProcessor):
    """Replace the location/operation location uri in a request/response body."""

    def __init__(self):
        self._replacement = "https://redacted.cognitiveservices.azure.com/translator"

    def process_response(self, response):
        try:
            headers = response['headers']
            if 'operation-location' in headers:
                location_header = "operation-location"
                if isinstance(headers[location_header], list):
                    suffix = headers[location_header][0].split("/translator/")[1]
                    response['headers'][location_header] = [self._replacement + suffix]
                else:
                    suffix = headers[location_header].split("/translator/")[1]
                    response['headers'][location_header] = self._replacement + suffix
            url = response["url"]
            if url is not None:
                suffix = url.split("/translator/")[1]
                response['url'] = self._replacement + suffix
            return response
        except (KeyError, ValueError):
            return response


class DocumentTranslationTest(AzureTestCase):
    FILTER_HEADERS = ReplayableTest.FILTER_HEADERS + ['Ocp-Apim-Subscription-Key']

    def __init__(self, method_name):
        super(DocumentTranslationTest, self).__init__(method_name)
        self.vcr.match_on = ["path", "method", "query"]
        self.recording_processors.append(OperationLocationReplacer())
        self.storage_name = os.getenv("DOCUMENTTRANSLATION_STORAGE_NAME", "redacted")
        self.storage_endpoint = "https://" + self.storage_name + ".blob.core.windows.net/"
        self.storage_key = os.getenv("DOCUMENTTRANSLATION_STORAGE_KEY")
        self.scrubber.register_name_pair(
            self.storage_endpoint, "https://redacted.blob.core.windows.net/"
        )
        self.scrubber.register_name_pair(
            self.storage_name, "redacted"
        )
        self.scrubber.register_name_pair(
            self.storage_key, "fakeZmFrZV9hY29jdW50X2tleQ=="
        )

    def _setup(self, data=None, blob_prefix=""):
        """Creates a source and target container.

        Pass data in as bytes (or as a list[bytes] to create more than one blob) in the source container.
        """
        self.source_container_sas_url = self.create_source_container(
            data=data or b'This is written in english.',
            blob_prefix=blob_prefix
        )
        self.target_container_sas_url = self.create_target_container()

    def create_source_container(self, data, blob_prefix=""):
        # for offline tests
        if not self.is_live:
            return "dummy_string"

        # for actual live tests
        container_name = "src" + str(uuid.uuid4())
        container_client = ContainerClient(self.storage_endpoint, container_name,
                                           self.storage_key)
        container_client.create_container()
        if isinstance(data, list):
            for blob in data:
                container_client.upload_blob(name=blob_prefix+str(uuid.uuid4()) + ".txt", data=blob)
        else:
            container_client.upload_blob(name=blob_prefix+str(uuid.uuid4())+".txt", data=data)
        return self.generate_sas_url(container_name, "rl")

    def create_target_container(self):
        # for offline tests
        if not self.is_live:
            return "dummy_string"

        # for actual live tests
        container_name = "target" + str(uuid.uuid4())
        container_client = ContainerClient(self.storage_endpoint, container_name,
                                           self.storage_key)
        container_client.create_container()

        return self.generate_sas_url(container_name, "racwdl")

    def generate_sas_url(self, container_name, permission):

        sas_token = self.generate_sas(
            generate_container_sas,
            account_name=self.storage_name,
            container_name=container_name,
            account_key=self.storage_key,
            permission=permission,
            expiry=datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        )

        container_sas_url = self.storage_endpoint + container_name + "?" + sas_token
        return container_sas_url

    def wait(self, duration=30):
        if self.is_live:
            time.sleep(duration)


    # model helpers
    def _validate_doc_status(self, doc_details, target_language):
        # specific assertions
        self.assertEqual(doc_details.status, "Succeeded")
        self.assertIsNotNone(doc_details.translate_to, target_language)
        # generic assertions
        self.assertIsNotNone(doc_details.id)
        self.assertIsNotNone(doc_details.translated_document_url)
        self.assertIsNotNone(doc_details.translation_progress)
        self.assertIsNotNone(doc_details.characters_charged)
        self.assertIsNotNone(doc_details.created_on)
        self.assertIsNotNone(doc_details.last_updated_on)

    def _validate_translation_job(self, job_details, total_docs_count, status):
        # status
        self.assertEqual(job_details.status, status)
        # docs count
        self.assertEqual(job_details.documents_total_count, total_docs_count)
        self.assertEqual(job_details.documents_failed_count, 0)
        self.assertEqual(job_details.documents_succeeded_count, total_docs_count)
        self.assertEqual(job_details.documents_in_progress_count, 0)
        self.assertEqual(job_details.documents_not_yet_started_count, 0)
        self.assertEqual(job_details.documents_cancelled_count, 0)
        # generic assertions
        self.assertIsNotNone(job_details.id)
        self.assertIsNotNone(job_details.created_on)
        self.assertIsNotNone(job_details.last_updated_on)
        self.assertIsNotNone(job_details.total_characters_charged)

    def _validate_format(self, format):
        self.assertIsNotNone(format.format)
        self.assertIsNotNone(format.file_extensions)
        self.assertIsNotNone(format.content_types)
        self.assertIsNotNone(format.format_versions)


    # client helpers
    def _submit_and_validate_translation_job(self, client, translation_inputs, total_docs_count):
        # submit job
        job_details = client.create_translation_job(translation_inputs)
        self.assertIsNotNone(job_details.id)
        # wait for result
        job_details = client.wait_until_done(job_details.id)
        # validate
        self._validate_translation_job(job_details, total_docs_count, "Succeeded")

        return job_details.id

    async def _submit_and_validate_translation_job_async(self, async_client, translation_inputs, total_docs_count):
        # submit job
        job_details = await async_client.create_translation_job(translation_inputs)
        self.assertIsNotNone(job_details.id)
        # wait for result
        job_details = await async_client.wait_until_done(job_details.id)
        # validate
        self._validate_translation_job(job_details, total_docs_count, "Succeeded")

        return job_details.id

    def _create_and_submit_sample_translation_jobs(self, client, jobs_count):
        for i in range(jobs_count):
            # prepare containers and test data
            '''
                WARNING!!
                TOTAL_DOC_COUNT_IN_JOB = 1
                if you plan to create more docs in the job,
                please update this variable TOTAL_DOC_COUNT_IN_JOB in respective test
            '''
            blob_data = b'This is some text'  # TOTAL_DOC_COUNT_IN_JOB = 1
            source_container_sas_url = self.create_source_container(data=blob_data)
            target_container_sas_url = self.create_target_container()

            # prepare translation inputs
            translation_inputs = [
                DocumentTranslationInput(
                    source_url=source_container_sas_url,
                    targets=[
                        TranslationTarget(
                            target_url=target_container_sas_url,
                            language_code="es"
                        )
                    ]
                )
            ]

            # submit multiple jobs
            job_details = client.create_translation_job(translation_inputs)
            self.assertIsNotNone(job_details.id)
            client.wait_until_done(job_details.id)

    async def _create_and_submit_sample_translation_jobs_async(self, async_client, jobs_count):
        for i in range(jobs_count):
            # prepare containers and test data
            '''
                # WARNING!!
                TOTAL_DOC_COUNT_IN_JOB = 1
                if you plan to create more docs in the job,
                please update this variable TOTAL_DOC_COUNT_IN_JOB in respective test

                # note
                since we're only testing the client library
                we can use sync container calls in here
                no need for async container clients!
            '''
            blob_data = b'This is some text'  
            source_container_sas_url = self.create_source_container(data=blob_data)
            target_container_sas_url = self.create_target_container()

            # prepare translation inputs
            translation_inputs = [
                DocumentTranslationInput(
                    source_url=source_container_sas_url,
                    targets=[
                        TranslationTarget(
                            target_url=target_container_sas_url,
                            language_code="es"
                        )
                    ]
                )
            ]

            # submit multiple jobs
            job_details = await async_client.create_translation_job(translation_inputs)
            self.assertIsNotNone(job_details.id)
            await async_client.wait_until_done(job_details.id)