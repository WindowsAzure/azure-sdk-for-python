# coding=utf-8
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import pytest
from azure.ai.textanalytics.protocol import TextAnalyticsPreparers
from azure.core.pipeline.transport import HttpRequest


def test_entities_recognition_general(client, documents):
    request = HttpRequest(
        "POST",
        url='/text/analytics/v3.0/entities/recognition/general',
        json={
            "documents": documents
        },
    )
    response = client.send_request(request)
    response.raise_for_status()

    json_response = response.json()

    assert len(json_response['documents'][0]['entities']) == 4

def test_entities_recognition_general_full_path(client, documents):
    request = HttpRequest(
        "POST",
        url='https://python-textanalytics.cognitiveservices.azure.com/text/analytics/v3.0/entities/recognition/general',
        json={
            "documents": documents
        },
    )
    response = client.send_request(request)
    response.raise_for_status()

    json_response = response.json()

    assert len(json_response['documents'][0]['entities']) == 4

def test_entities_recognition_general_preparer(client, documents):
    request = TextAnalyticsPreparers.prepare_entities_recognition_general(
        api_version="v3.0",
        body={
            "documents": documents
        },
    )
    response = client.send_request(request)
    response.raise_for_status()

    json_response = response.json()
    assert len(json_response['documents'][0]['entities']) == 4

def test_entities_linking_preparer(client, documents):
    request = TextAnalyticsPreparers.prepare_entities_linking(
        api_version="v3.0",
        body={
            "documents": documents
        },
    )
    response = client.send_request(request)
    response.raise_for_status()
    json_response = response.json()
    assert json_response['documents'][0]['entities'][0]['matches'][0]['text'] == "Microsoft"

def test_entities_recognition_pii_preparer(client, documents):
    with pytest.raises(ValueError) as ex:
        TextAnalyticsPreparers.prepare_entities_recognition_pii(
            api_version="v3.0",
            body={
                "documents": documents
            },
        )

    assert "API version v3.0 does not have operation 'prepare_entities_recognition_pii'" in str(ex.value)

def test_languages_preparer(client, documents):
    request = TextAnalyticsPreparers.prepare_languages(
        api_version="v3.0",
        body={
            "documents": documents
        },
    )
    response = client.send_request(request)
    response.raise_for_status()
    json_response = response.json()
    assert json_response['documents'][0]['detectedLanguage']['name'] == 'English'
    assert json_response['documents'][1]['detectedLanguage']['name'] == 'Chinese_Simplified'

def test_sentiment_preparer(client, documents):
    request = TextAnalyticsPreparers.prepare_sentiment(
        api_version="v3.0",
        body={
            "documents": documents
        },
    )
    response = client.send_request(request)
    response.raise_for_status()
    json_response = response.json()
    assert json_response['documents'][0]['sentiment'] == 'positive'
    assert json_response['documents'][1]['sentiment'] == 'positive'

def test_query_params(client, documents):
    request = TextAnalyticsPreparers.prepare_sentiment(
        api_version="v3.0",
        body={
            "documents": documents
        },
        show_stats=True
    )
    response = client.send_request(request)
    response.raise_for_status()
    json_response = response.json()
    assert json_response['documents'][0]['sentiment'] == 'positive'
    assert json_response['documents'][1]['sentiment'] == 'positive'
    assert json_response['statistics']['documentsCount'] == 3