# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

import functools
from testcase import Document
from asynctestcase import AsyncDocumentTranslationTest
from preparer import DocumentTranslationPreparer, DocumentTranslationClientPreparer as _DocumentTranslationClientPreparer
from azure.ai.translation.documents import DocumentTranslationInput, TranslationTarget
from azure.ai.translation.documents.aio import DocumentTranslationClient
DocumentTranslationClientPreparer = functools.partial(_DocumentTranslationClientPreparer, DocumentTranslationClient)


class DocumentStatus(AsyncDocumentTranslationTest):

    @DocumentTranslationPreparer()
    @DocumentTranslationClientPreparer()
    async def test_list_statuses(self, client):
        # prepare containers and test data
        blob_data = [Document(data=b'This is some text')]
        source_container_sas_url = self.create_source_container(data=blob_data)
        target_container_sas_url = self.create_target_container()
        target_language = "es"

        # prepare translation inputs
        translation_inputs = [
            DocumentTranslationInput(
                source_url=source_container_sas_url,
                targets=[
                    TranslationTarget(
                        target_url=target_container_sas_url,
                        language_code=target_language
                    )
                ]
            )
        ]

        # submit and validate translation job
        job_id = await self._submit_and_validate_translation_job_async(client, translation_inputs, len(blob_data))

        # get doc statuses
        doc_statuses = client.list_all_document_statuses(job_id)
        self.assertIsNotNone(doc_statuses)

        # get first doc
        first_doc = await doc_statuses.__anext__()
        self.assertIsNotNone(first_doc.id)

        # get doc details
        doc_status = await client.get_document_status(job_id=job_id, document_id=first_doc.id)
        self._validate_doc_status(doc_status, target_language)