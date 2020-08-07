#-------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#--------------------------------------------------------------------------

import logging
import sys
import os
import pytest
import json
import datetime as dt

from devtools_testutils import AzureMgmtTestCase
from msrest.serialization import UTC
from azure.eventgrid import EventGridConsumer, CloudEvent, EventGridEvent, StorageBlobCreatedEventData

# storage cloud event
cloud_storage_dict = {
    "id":"a0517898-9fa4-4e70-b4a3-afda1dd68672",
    "source":"/subscriptions/{subscription-id}/resourceGroups/{resource-group}/providers/Microsoft.Storage/storageAccounts/{storage-account}",
    "data":{
        "api":"PutBlockList",
        "client_request_id":"6d79dbfb-0e37-4fc4-981f-442c9ca65760",
        "request_id":"831e1650-001e-001b-66ab-eeb76e000000",
        "e_tag":"0x8D4BCC2E4835CD0",
        "content_type":"application/octet-stream",
        "content_length":524288,
        "blob_type":"BlockBlob",
        "url":"https://oc2d2817345i60006.blob.core.windows.net/oc2d2817345i200097container/oc2d2817345i20002296blob",
        "sequencer":"00000000000004420000000000028963",
        "storage_diagnostics":{"batchId":"b68529f3-68cd-4744-baa4-3c0498ec19f0"}
    },
    "type":"Microsoft.Storage.BlobCreated",
    "time":"2020-08-07T01:11:49.765846Z",
    "specversion":"1.0"
}
cloud_storage_string = json.dumps(cloud_storage_dict)
cloud_storage_bytes = bytes(cloud_storage_string, "utf-8")

# custom cloud event
cloud_custom_dict = {
    "id":"de0fd76c-4ef4-4dfb-ab3a-8f24a307e033",
    "source":"https://egtest.dev/cloudcustomevent",
    "data":{"team": "event grid squad"},
    "type":"Azure.Sdk.Sample",
    "time":"2020-08-07T02:06:08.11969Z",
    "specversion":"1.0"
}
cloud_custom_string = json.dumps(cloud_custom_dict)
cloud_custom_bytes = bytes(cloud_custom_string, "utf-8")

# storage eg event
eg_storage_dict = {
    "id":"bbab6625-dc56-4b22-abeb-afcc72e5290c",
    "subject":"/blobServices/default/containers/oc2d2817345i200097container/blobs/oc2d2817345i20002296blob",
    "data":{
        "api":"PutBlockList",
        "clientRequestId":"6d79dbfb-0e37-4fc4-981f-442c9ca65760",
        "requestId":"831e1650-001e-001b-66ab-eeb76e000000",
        "eTag":"0x8D4BCC2E4835CD0",
        "contentType":"application/octet-stream",
        "contentLength":524288,
        "blobType":"BlockBlob",
        "url":"https://oc2d2817345i60006.blob.core.windows.net/oc2d2817345i200097container/oc2d2817345i20002296blob",
        "sequencer":"00000000000004420000000000028963",
        "storageDiagnostics":{"batchId":"b68529f3-68cd-4744-baa4-3c0498ec19f0"}
    },
    "eventType":"Microsoft.Storage.BlobCreated",
    "dataVersion":"2.0",
    "metadataVersion":"1",
    "eventTime":"2020-08-07T02:28:23.867525Z",
    "topic":"/subscriptions/faa080af-c1d8-40ad-9cce-e1a450ca5b57/resourceGroups/t-swpill-test/providers/Microsoft.EventGrid/topics/eventgridegsub"
}

eg_storage_string = json.dumps(eg_storage_dict)
eg_storage_bytes = bytes(eg_storage_string, "utf-8")

# custom eg event
eg_custom_dict = {
    "id":"3a30afef-b604-4b67-973e-7dfff7e178a7",
    "subject":"Test EG Custom Event",
    "data":{"team":"event grid squad"},
    "eventType":"Azure.Sdk.Sample",
    "dataVersion":"2.0",
    "metadataVersion":"1",
    "eventTime":"2020-08-07T02:19:05.16916Z",
    "topic":"/subscriptions/f8aa80ae-d1c8-60ad-9bce-e1a850ba5b67/resourceGroups/sample-resource-group-test/providers/Microsoft.EventGrid/topics/egtopicsamplesub"
}
eg_custom_string = json.dumps(eg_custom_dict)
eg_custom_bytes = bytes(eg_custom_string, "utf-8")

class EventGridConsumerTests(AzureMgmtTestCase):

    # Cloud Event tests
    @pytest.mark.liveTest
    def test_eg_consumer_cloud_storage_dict(self, **kwargs):
        client = EventGridConsumer()
        deserialized_event = client.deserialize_event(cloud_storage_dict)
        event_json = deserialized_event.to_json()
        assert deserialized_event.model.__class__ == CloudEvent
        assert deserialized_event.model.data.__class__ == StorageBlobCreatedEventData
        assert event_json.__class__ == dict

    @pytest.mark.liveTest
    def test_eg_consumer_cloud_storage_string(self, **kwargs):
        client = EventGridConsumer()
        deserialized_event = client.deserialize_event(cloud_storage_string)
        event_json = deserialized_event.to_json()
        assert deserialized_event.model.__class__ == CloudEvent
        assert deserialized_event.model.data.__class__ == StorageBlobCreatedEventData
        assert event_json.__class__ == dict

    @pytest.mark.liveTest
    def test_eg_consumer_cloud_storage_bytes(self, **kwargs):
        client = EventGridConsumer()
        deserialized_event = client.deserialize_event(cloud_storage_bytes)
        event_json = deserialized_event.to_json()
        assert deserialized_event.model.__class__ == CloudEvent
        assert deserialized_event.model.data.__class__ == StorageBlobCreatedEventData
        assert event_json.__class__ == dict
    
    @pytest.mark.liveTest
    def test_eg_consumer_cloud_custom_dict(self, **kwargs):
        client = EventGridConsumer()
        deserialized_event = client.deserialize_event(cloud_custom_dict)
        event_json = deserialized_event.to_json()
        assert deserialized_event.model.__class__ == CloudEvent
        assert deserialized_event.model.data is None
        assert event_json.__class__ == dict

    @pytest.mark.liveTest
    def test_eg_consumer_cloud_custom_string(self, **kwargs):
        client = EventGridConsumer()
        deserialized_event = client.deserialize_event(cloud_custom_string)
        event_json = deserialized_event.to_json()
        assert deserialized_event.model.__class__ == CloudEvent
        assert deserialized_event.model.data is None
        assert event_json.__class__ == dict

    @pytest.mark.liveTest
    def test_eg_consumer_cloud_custom_bytes(self, **kwargs):
        client = EventGridConsumer()
        deserialized_event = client.deserialize_event(cloud_custom_bytes)
        event_json = deserialized_event.to_json()
        assert deserialized_event.model.__class__ == CloudEvent
        assert deserialized_event.model.data is None
        assert event_json.__class__ == dict
    
    # EG Event tests
    @pytest.mark.liveTest
    def test_eg_consumer_eg_storage_dict(self, **kwargs):
        client = EventGridConsumer()
        deserialized_event = client.deserialize_event(eg_storage_dict)
        event_json = deserialized_event.to_json()
        assert deserialized_event.model.__class__ == EventGridEvent
        assert deserialized_event.model.data.__class__ == StorageBlobCreatedEventData
        assert event_json.__class__ == dict

    @pytest.mark.liveTest
    def test_eg_consumer_eg_storage_string(self, **kwargs):
        client = EventGridConsumer()
        deserialized_event = client.deserialize_event(eg_storage_string)
        event_json = deserialized_event.to_json()
        assert deserialized_event.model.__class__ == EventGridEvent
        assert deserialized_event.model.data.__class__ == StorageBlobCreatedEventData
        assert event_json.__class__ == dict

    @pytest.mark.liveTest
    def test_eg_consumer_eg_storage_bytes(self, **kwargs):
        client = EventGridConsumer()
        deserialized_event = client.deserialize_event(eg_storage_bytes)
        event_json = deserialized_event.to_json()
        assert deserialized_event.model.__class__ == EventGridEvent
        assert deserialized_event.model.data.__class__ == StorageBlobCreatedEventData
        assert event_json.__class__ == dict
    
    @pytest.mark.liveTest
    def test_eg_consumer_eg_custom_dict(self, **kwargs):
        client = EventGridConsumer()
        deserialized_event = client.deserialize_event(eg_custom_dict)
        event_json = deserialized_event.to_json()
        assert deserialized_event.model.__class__ == EventGridEvent
        assert deserialized_event.model.data is None
        assert event_json.__class__ == dict

    @pytest.mark.liveTest
    def test_eg_consumer_eg_custom_string(self, **kwargs):
        client = EventGridConsumer()
        deserialized_event = client.deserialize_event(eg_custom_string)
        event_json = deserialized_event.to_json()
        assert deserialized_event.model.__class__ == EventGridEvent
        assert deserialized_event.model.data is None
        assert event_json.__class__ == dict

    @pytest.mark.liveTest
    def test_eg_consumer_eg_custom_bytes(self, **kwargs):
        client = EventGridConsumer()
        deserialized_event = client.deserialize_event(eg_custom_bytes)
        event_json = deserialized_event.to_json()
        assert deserialized_event.model.__class__ == EventGridEvent
        assert deserialized_event.model.data is None
        assert event_json.__class__ == dict
