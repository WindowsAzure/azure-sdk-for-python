# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

import functools
from testcase import DocumentTranslationTest
from preparer import DocumentTranslationPreparer, DocumentTranslationClientPreparer as _DocumentTranslationClientPreparer
from azure.ai.documenttranslation import DocumentTranslationClient, DocumentTranslationInput, TranslationTarget
DocumentTranslationClientPreparer = functools.partial(_DocumentTranslationClientPreparer, DocumentTranslationClient)


class TestTranslation(DocumentTranslationTest):

    @DocumentTranslationPreparer()
    @DocumentTranslationClientPreparer()
    def test_single_source_single_target(self, client):
        self._setup()  # set up test resources

        # prepare translation inputs
        translation_inputs = [
            DocumentTranslationInput(
                source_url=self.source_container_sas_url,
                targets=[
                    TranslationTarget(
                        target_url=self.target_container_sas_url,
                        language_code="es"
                    )
                ]
            )
        ]

        # submit job
        job_detail = client.create_translation_job(translation_inputs)
        self.assertIsNotNone(job_detail.id)

        # wait for result
        job_result = client.wait_until_done(job_detail.id)

        # assert
        self.assertEqual(job_result.status, "Succeeded")  # job succeeded
        self.assertIsNotNone(job_result.created_on)
        self.assertIsNotNone(job_result.last_updated_on)
        self.assertIsNotNone(job_result.documents_total_count)
        self.assertIsNotNone(job_result.documents_failed_count)
        self.assertIsNotNone(job_result.documents_succeeded_count)
        self.assertIsNotNone(job_result.documents_in_progress_count)
        self.assertIsNotNone(job_result.documents_not_yet_started_count)
        self.assertIsNotNone(job_result.documents_cancelled_count)
        self.assertIsNotNone(job_result.total_characters_charged)


    @DocumentTranslationPreparer()
    @DocumentTranslationClientPreparer()
    def test_single_source_two_targets(self, client):
        self._setup()  # set up test resources

        # prepare translation inputs
        translation_inputs = [
            DocumentTranslationInput(
                source_url=self.source_container_sas_url,
                targets=[
                    TranslationTarget(
                        target_url=self.target_container_sas_url,
                        language_code="es"
                    ),
                    TranslationTarget(
                        target_url=self.additional_target_container_sas_url,
                        language_code="fr"
                    )
                ]
            )
        ]

        # submit job
        job_detail = client.create_translation_job(translation_inputs)
        self.assertIsNotNone(job_detail.id)

        # wait for result
        job_result = client.wait_until_done(job_detail.id)

        # assert
        self.assertEqual(job_result.status, "Succeeded")  # job succeeded
        self.assertIsNotNone(job_result.created_on)
        self.assertIsNotNone(job_result.last_updated_on)
        self.assertIsNotNone(job_result.documents_total_count)
        self.assertIsNotNone(job_result.documents_failed_count)
        self.assertIsNotNone(job_result.documents_succeeded_count)
        self.assertIsNotNone(job_result.documents_in_progress_count)
        self.assertIsNotNone(job_result.documents_not_yet_started_count)
        self.assertIsNotNone(job_result.documents_cancelled_count)
        self.assertIsNotNone(job_result.total_characters_charged)

    @DocumentTranslationPreparer()
    @DocumentTranslationClientPreparer()
    def test_multiple_sources_single_target(self, client):
        self._setup()  # set up test resources

        # prepare translation inputs
        translation_inputs = [
            DocumentTranslationInput(
                source_url=self.source_container_sas_url,
                targets=[
                    TranslationTarget(
                        target_url=self.target_container_sas_url,
                        language_code="es"
                    )
                ]
            ),
            DocumentTranslationInput(
                source_url=self.additional_source_container_sas_url,
                targets=[
                    TranslationTarget(
                        target_url=self.additional_target_container_sas_url,
                        language_code="fr"
                    )
                ]
            )
        ]

        # submit job
        job_detail = client.create_translation_job(translation_inputs)
        self.assertIsNotNone(job_detail.id)

        # wait for result
        job_result = client.wait_until_done(job_detail.id)

        # assert
        self.assertEqual(job_result.status, "Succeeded")  # job succeeded
        self.assertIsNotNone(job_result.created_on)
        self.assertIsNotNone(job_result.last_updated_on)
        self.assertIsNotNone(job_result.documents_total_count)
        self.assertIsNotNone(job_result.documents_failed_count)
        self.assertIsNotNone(job_result.documents_succeeded_count)
        self.assertIsNotNone(job_result.documents_in_progress_count)
        self.assertIsNotNone(job_result.documents_not_yet_started_count)
        self.assertIsNotNone(job_result.documents_cancelled_count)
        self.assertIsNotNone(job_result.total_characters_charged)


    @DocumentTranslationPreparer()
    @DocumentTranslationClientPreparer()
    def test_single_source_single_target_with_prefix(self, client):
        self._setup()  # set up test resources

        # prepare translation inputs
        translation_inputs = [
            DocumentTranslationInput(
                source_url=self.source_container_sas_url,
                targets=[
                    TranslationTarget(
                        target_url=self.target_container_sas_url,
                        language_code="es"
                    )
                ],
                prefix="src"
            )
        ]

        # submit job
        job_detail = client.create_translation_job(translation_inputs)
        self.assertIsNotNone(job_detail.id)

        # wait for result
        job_result = client.wait_until_done(job_detail.id)

        # assert
        self.assertEqual(job_result.status, "Succeeded")  # job succeeded
        self.assertIsNotNone(job_result.created_on)
        self.assertIsNotNone(job_result.last_updated_on)
        self.assertIsNotNone(job_result.documents_total_count)
        self.assertIsNotNone(job_result.documents_failed_count)
        self.assertIsNotNone(job_result.documents_succeeded_count)
        self.assertIsNotNone(job_result.documents_in_progress_count)
        self.assertIsNotNone(job_result.documents_not_yet_started_count)
        self.assertIsNotNone(job_result.documents_cancelled_count)
        self.assertIsNotNone(job_result.total_characters_charged)


    @DocumentTranslationPreparer()
    @DocumentTranslationClientPreparer()
    def test_single_source_single_target_with_prefix(self, client):
        self._setup()  # set up test resources

        # prepare translation inputs
        translation_inputs = [
            DocumentTranslationInput(
                source_url=self.source_container_sas_url,
                targets=[
                    TranslationTarget(
                        target_url=self.target_container_sas_url,
                        language_code="es"
                    )
                ],
                suffix="txt"
            )
        ]

        # submit job
        job_detail = client.create_translation_job(translation_inputs)
        self.assertIsNotNone(job_detail.id)

        # wait for result
        job_result = client.wait_until_done(job_detail.id)

        # assert
        self.assertEqual(job_result.status, "Succeeded")  # job succeeded
        self.assertIsNotNone(job_result.created_on)
        self.assertIsNotNone(job_result.last_updated_on)
        self.assertIsNotNone(job_result.documents_total_count)
        self.assertIsNotNone(job_result.documents_failed_count)
        self.assertIsNotNone(job_result.documents_succeeded_count)
        self.assertIsNotNone(job_result.documents_in_progress_count)
        self.assertIsNotNone(job_result.documents_not_yet_started_count)
        self.assertIsNotNone(job_result.documents_cancelled_count)
        self.assertIsNotNone(job_result.total_characters_charged)
