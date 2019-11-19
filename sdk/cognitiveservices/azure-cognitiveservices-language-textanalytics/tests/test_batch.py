# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

import pytest

from devtools_testutils import ResourceGroupPreparer
from devtools_testutils.cognitiveservices_testcase import CognitiveServiceTest, CognitiveServicesAccountPreparer
from azure.cognitiveservices.language.textanalytics import (
    TextAnalyticsClient,
    LanguageInput,
    MultiLanguageInput
)
from azure.cognitiveservices.language.textanalytics import DocumentEntities


class TextAnalyticsTest(CognitiveServiceTest):

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_successful_detect_language(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "text": "I should take my cat to the veterinarian."},
                {"id": "2", "text": "Este es un document escrito en Español."},
                {"id": "3", "text": "猫は幸せ"},
                {"id": "4", "text": "Fahrt nach Stuttgart und dann zum Hotel zu Fu."}]

        response = text_analytics.detect_language(docs)

        self.assertEqual(response[0].detected_languages[0].name, "English")
        self.assertEqual(response[1].detected_languages[0].name, "Spanish")
        self.assertEqual(response[2].detected_languages[0].name, "Japanese")
        self.assertEqual(response[3].detected_languages[0].name, "German")

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_some_errors_detect_language(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "country_hint": "United States", "text": "I should take my cat to the veterinarian."},
                {"id": "2", "text": "Este es un document escrito en Español."},
                {"id": "3", "text": ""},
                {"id": "4", "text": "Fahrt nach Stuttgart und dann zum Hotel zu Fu."}]

        response = text_analytics.detect_language(docs)

        self.assertTrue(response[0].is_error)
        self.assertFalse(response[1].is_error)
        self.assertTrue(response[2].is_error)
        self.assertFalse(response[3].is_error)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_all_errors_detect_language(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)
        text = ""
        for _ in range(5121):
            text += "x"

        docs = [{"id": "1", "text": ""},
                {"id": "2", "text": ""},
                {"id": "3", "text": ""},
                {"id": "4", "text": text}]

        response = text_analytics.detect_language(docs)

        for resp in response:
            self.assertTrue(resp.is_error)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_successful_recognize_entities(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "language": "en", "text": "Microsoft was founded by Bill Gates and Paul Allen on April 4, 1975."},
                {"id": "2", "language": "es", "text": "Microsoft fue fundado por Bill Gates y Paul Allen el 4 de abril de 1975."},
                {"id": "3", "language": "de", "text": "Microsoft wurde am 4. April 1975 von Bill Gates und Paul Allen gegründet."}]

        response = text_analytics.recognize_entities(docs)
        for doc in response:
            self.assertEqual(len(doc.entities), 4)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_some_errors_recognize_entities(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "language": "en", "text": "Microsoft was founded by Bill Gates and Paul Allen on April 4, 1975."},
                {"id": "2", "language": "Spanish", "text": "Hola"},
                {"id": "3", "language": "de", "text": ""}]

        response = text_analytics.recognize_entities(docs)
        self.assertFalse(response[0].is_error)
        self.assertTrue(response[1].is_error)
        self.assertTrue(response[2].is_error)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_all_errors_recognize_entities(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "text": ""},
                {"id": "2", "language": "Spanish", "text": "Hola"},
                {"id": "3", "language": "de", "text": ""}]

        response = text_analytics.recognize_entities(docs)
        self.assertTrue(response[0].is_error)
        self.assertTrue(response[1].is_error)
        self.assertTrue(response[2].is_error)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_successful_recognize_pii_entities(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "text": "My SSN is 555-55-5555."},
                {"id": "2", "text": "Your ABA number - 111000025 - is the first 9 digits in the lower left hand corner of your personal check."},
                {"id": "3", "text": "Is 998.214.865-68 your Brazilian CPF number?"}]

        response = text_analytics.recognize_pii_entities(docs)
        self.assertEqual(response[0].entities[0].text, "555-55-5555")
        self.assertEqual(response[0].entities[0].type, "U.S. Social Security Number (SSN)")
        self.assertEqual(response[1].entities[0].text, "111000025")
        self.assertEqual(response[1].entities[0].type, "ABA Routing Number")
        self.assertEqual(response[2].entities[0].text, "998.214.865-68")
        self.assertEqual(response[2].entities[0].type, "Brazil CPF Number")

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_some_errors_recognize_pii_entities(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "language": "es", "text": "hola"},
                {"id": "2", "text": ""},
                {"id": "3", "text": "Is 998.214.865-68 your Brazilian CPF number?"}]

        response = text_analytics.recognize_pii_entities(docs)
        self.assertTrue(response[0].is_error)
        self.assertTrue(response[1].is_error)
        self.assertFalse(response[2].is_error)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_all_errors_recognize_pii_entities(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "language": "es", "text": "hola"},
                {"id": "2", "text": ""}]

        response = text_analytics.recognize_pii_entities(docs)
        self.assertTrue(response[0].is_error)
        self.assertTrue(response[1].is_error)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_successful_recognize_linked_entities(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "language": "en", "text": "Microsoft was founded by Bill Gates and Paul Allen"},
                {"id": "2", "language": "es", "text": "Microsoft fue fundado por Bill Gates y Paul Allen"}]

        response = text_analytics.recognize_linked_entities(docs)
        for doc in response:
            self.assertEqual(len(doc.entities), 3)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_some_errors_recognize_linked_entities(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "text": ""},
                {"id": "2", "language": "es", "text": "Microsoft fue fundado por Bill Gates y Paul Allen"}]

        response = text_analytics.recognize_linked_entities(docs)
        self.assertTrue(response[0].is_error)
        self.assertFalse(response[1].is_error)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_all_errors_recognize_linked_entities(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "text": ""},
                {"id": "2", "language": "Spanish", "text": "Microsoft fue fundado por Bill Gates y Paul Allen"}]

        response = text_analytics.recognize_linked_entities(docs)
        self.assertTrue(response[0].is_error)
        self.assertTrue(response[1].is_error)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_successful_extract_key_phrases(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "language": "en", "text": "Microsoft was founded by Bill Gates and Paul Allen"},
                {"id": "2", "language": "es", "text": "Microsoft fue fundado por Bill Gates y Paul Allen"}]

        response = text_analytics.extract_key_phrases(docs)
        for phrases in response:
            self.assertIn("Paul Allen", phrases.key_phrases)
            self.assertIn("Bill Gates", phrases.key_phrases)
            self.assertIn("Microsoft", phrases.key_phrases)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_some_errors_extract_key_phrases(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "language": "English", "text": "Microsoft was founded by Bill Gates and Paul Allen"},
                {"id": "2", "language": "es", "text": "Microsoft fue fundado por Bill Gates y Paul Allen"}]

        response = text_analytics.extract_key_phrases(docs)
        self.assertTrue(response[0].is_error)
        self.assertFalse(response[1].is_error)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_all_errors_extract_key_phrases(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "language": "English", "text": "Microsoft was founded by Bill Gates and Paul Allen"},
                {"id": "2", "language": "es", "text": ""}]

        response = text_analytics.extract_key_phrases(docs)
        self.assertTrue(response[0].is_error)
        self.assertTrue(response[1].is_error)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_successful_analyze_sentiment(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "language": "en", "text": "Microsoft was founded by Bill Gates and Paul Allen."},
                {"id": "2", "language": "en", "text": "I did not like the hotel we stayed it. It was too expensive."},
                {"id": "3", "language": "en", "text": "The restaurant had really good food. I recommend you try it."}]

        response = text_analytics.analyze_sentiment(docs)
        self.assertEqual(response[0].sentiment, "neutral")
        self.assertEqual(response[1].sentiment, "negative")
        self.assertEqual(response[2].sentiment, "positive")

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_some_errors_analyze_sentiment(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "language": "en", "text": ""},
                {"id": "2", "language": "english", "text": "I did not like the hotel we stayed it. It was too expensive."},
                {"id": "3", "language": "en", "text": "The restaurant had really good food. I recommend you try it."}]

        response = text_analytics.analyze_sentiment(docs)
        self.assertTrue(response[0].is_error)
        self.assertTrue(response[1].is_error)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_all_errors_analyze_sentiment(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "1", "language": "en", "text": ""},
                {"id": "2", "language": "english", "text": "I did not like the hotel we stayed it. It was too expensive."},
                {"id": "3", "language": "en", "text": ""}]

        response = text_analytics.analyze_sentiment(docs)
        self.assertTrue(response[0].is_error)
        self.assertTrue(response[1].is_error)
        self.assertTrue(response[2].is_error)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_validate_input_string(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [
            u"I should take my cat to the veterinarian.",
            u"Este es un document escrito en Español.",
            u"猫は幸せ",
            u"Fahrt nach Stuttgart und dann zum Hotel zu Fu.",
            u""
        ]

        response = text_analytics.detect_language(docs)
        self.assertEqual(response[0].detected_languages[0].name, "English")
        self.assertEqual(response[1].detected_languages[0].name, "Spanish")
        self.assertEqual(response[2].detected_languages[0].name, "Japanese")
        self.assertEqual(response[3].detected_languages[0].name, "German")
        self.assertTrue(response[4].is_error)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_validate_language_input(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [
            LanguageInput(id="1", text="I should take my cat to the veterinarian."),
            LanguageInput(id="2", text="Este es un document escrito en Español."),
            LanguageInput(id="3", text="猫は幸せ"),
            LanguageInput(id="4", text="Fahrt nach Stuttgart und dann zum Hotel zu Fu.")
        ]

        response = text_analytics.detect_language(docs)
        self.assertEqual(response[0].detected_languages[0].name, "English")
        self.assertEqual(response[1].detected_languages[0].name, "Spanish")
        self.assertEqual(response[2].detected_languages[0].name, "Japanese")
        self.assertEqual(response[3].detected_languages[0].name, "German")

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_validate_multilanguage_input(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [
            MultiLanguageInput(id="1", text="Microsoft was founded by Bill Gates and Paul Allen."),
            MultiLanguageInput(id="2", text="I did not like the hotel we stayed it. It was too expensive."),
            MultiLanguageInput(id="3", text="The restaurant had really good food. I recommend you try it."),
        ]

        response = text_analytics.analyze_sentiment(docs)
        self.assertEqual(response[0].sentiment, "neutral")
        self.assertEqual(response[1].sentiment, "negative")
        self.assertEqual(response[2].sentiment, "positive")

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_mixing_inputs(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)
        docs = [
            {"id": "1", "text": "Microsoft was founded by Bill Gates and Paul Allen."},
            MultiLanguageInput(id="2", text="I did not like the hotel we stayed it. It was too expensive."),
            u"You cannot mix string input with the above inputs"
        ]
        with self.assertRaises(TypeError):
            response = text_analytics.analyze_sentiment(docs)

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_out_of_order_ids(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = [{"id": "56", "text": ":)"},
                {"id": "0", "text": ":("},
                {"id": "22", "text": ""},
                {"id": "19", "text": ":P"},
                {"id": "1", "text": ":D"}]

        response = text_analytics.analyze_sentiment(docs)
        in_order = ["56", "0", "22", "19", "1"]
        for idx, resp in enumerate(response):
            self.assertEqual(resp.id, in_order[idx])

    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_show_stats_and_model_version(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        def callback(response):
            self.assertIsNotNone(response.model_version)
            self.assertIsNotNone(response.raw_response)
            self.assertEqual(response.statistics.documents_count, 5)
            self.assertEqual(response.statistics.transactions_count, 4)
            self.assertEqual(response.statistics.valid_documents_count, 4)
            self.assertEqual(response.statistics.erroneous_documents_count, 1)

        docs = [{"id": "56", "text": ":)"},
                {"id": "0", "text": ":("},
                {"id": "22", "text": ""},
                {"id": "19", "text": ":P"},
                {"id": "1", "text": ":D"}]

        response = text_analytics.analyze_sentiment(
            docs,
            show_stats=True,
            model_version="latest",
            response_hook=callback
        )

    @pytest.mark.live_test_only  # live test only because generates huge recording
    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_segment_batch(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = ["hello world"] * 3050
        response = text_analytics.detect_language(docs)

        self.assertEqual(len(response), 3050)
        for doc in response:
            self.assertEqual(doc.detected_languages[0].name, "English")

    @pytest.mark.live_test_only  # live test only because generates huge recording
    @ResourceGroupPreparer()
    @CognitiveServicesAccountPreparer(name_prefix="pycog")
    def test_segment_batch_with_500_batch_error_duplicated(self, resource_group, location, cognitiveservices_account, cognitiveservices_account_key):
        text_analytics = TextAnalyticsClient(cognitiveservices_account, cognitiveservices_account_key)

        docs = []
        for idx in range(1000):
            docs.append("Bill Gates founded Microsoft")  # first batch

        for idx in range(1000):
            docs.append("")  # this will cause a whole batch failure for the second batch

        for idx in range(50):
            docs.append("Bill Gates founded Microsoft")  # third batch

        response = text_analytics.recognize_entities(docs)

        self.assertEqual(len(response), 2050)
        for idx, doc in enumerate(response):
            if doc.is_error:
                self.assertTrue(2000 > idx >= 1000)
            else:
                self.assertTrue(isinstance(doc, DocumentEntities))
