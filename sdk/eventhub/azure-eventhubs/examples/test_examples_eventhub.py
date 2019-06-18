#-------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#--------------------------------------------------------------------------

import pytest
import datetime
import os
import time
import logging

from azure.eventhub import EventHubError


def create_eventhub_client(live_eventhub_config):
    # [START create_eventhub_client]
    import os
    from azure.eventhub import EventHubClient, EventHubSharedKeyCredential

    host = os.environ['EVENT_HUB_HOSTNAME']
    event_hub_path = os.environ['EVENT_HUB_NAME']
    shared_access_policy = os.environ['EVENT_HUB_SAS_POLICY']
    shared_access_key = os.environ['EVENT_HUB_SAS_KEY']

    client = EventHubClient(
        host=host,
        event_hub_path=event_hub_path,
        credential=EventHubSharedKeyCredential(shared_access_policy, shared_access_key)
    )
    # [END create_eventhub_client]
    return client


def create_eventhub_client_from_iothub_connection_string(live_eventhub_config):
    # [START create_eventhub_client_iot_connstr]
    import os
    from azure.eventhub import EventHubClient

    iot_connection_str = os.environ['IOTHUB_CONNECTION_STR']
    client = EventHubClient.from_iothub_connection_string(iot_connection_str)
    # [END create_eventhub_client_iot_connstr]


def test_example_eventhub_sync_send_and_receive(live_eventhub_config):
    # [START create_eventhub_client_connstr]
    import os
    from azure.eventhub import EventHubClient

    connection_str = "Endpoint=sb://{}/;SharedAccessKeyName={};SharedAccessKey={};EntityPath={}".format(
        os.environ['EVENT_HUB_HOSTNAME'],
        os.environ['EVENT_HUB_SAS_POLICY'],
        os.environ['EVENT_HUB_SAS_KEY'],
        os.environ['EVENT_HUB_NAME'])
    client = EventHubClient.from_connection_string(connection_str)
    # [END create_eventhub_client_connstr]

    from azure.eventhub import EventData, EventPosition

    # [START create_eventhub_client_sender]
    client = EventHubClient.from_connection_string(connection_str)
    # Create a sender.
    sender = client.create_sender(partition_id="0")
    # [END create_eventhub_client_sender]

    # [START create_eventhub_client_receiver]
    client = EventHubClient.from_connection_string(connection_str)
    # Create a receiver.
    receiver = client.create_receiver(partition_id="0", consumer_group="$default", event_position=EventPosition('@latest'))
    # Create an exclusive receiver object.
    exclusive_receiver = client.create_receiver(partition_id="0", event_position=EventPosition("-1"), exclusive_receiver_priority=1)
    # [END create_eventhub_client_receiver]

    client = EventHubClient.from_connection_string(connection_str)
    sender = client.create_sender(partition_id="0")
    receiver = client.create_receiver(partition_id="0", event_position=EventPosition('@latest'))
    try:
        receiver.receive(timeout=1)

        # [START create_event_data]
        event_data = EventData("String data")
        event_data = EventData(b"Bytes data")
        event_data = EventData([b"A", b"B", b"C"])

        list_data = ['Message {}'.format(i) for i in range(10)]
        event_data = EventData(body=list_data)
        # [END create_event_data]

        # [START eventhub_client_sync_send]
        with sender:
            event_data = EventData(b"A single event")
            sender.send(event_data)
        # [END eventhub_client_sync_send]
        time.sleep(1)

        # [START eventhub_client_sync_receive]
        with receiver:
            logger = logging.getLogger("azure.eventhub")
            received = receiver.receive(timeout=5, max_batch_size=1)
            for event_data in received:
                logger.info("Message received:{}".format(event_data.body_as_str()))
        # [END eventhub_client_sync_receive]
            assert len(received) == 1
            assert received[0].body_as_str() == "A single event"
            assert list(received[-1].body)[0] == b"A single event"
    finally:
        pass


def test_example_eventhub_sender_ops(live_eventhub_config, connection_str):
    from azure.eventhub import EventHubClient, EventData

    # [START eventhub_client_sender_close]
    client = EventHubClient.from_connection_string(connection_str)
    sender = client.create_sender(partition_id="0")
    try:
        sender.send(EventData(b"A single event"))
    finally:
        # Close down the send handler.
        sender.close()
    # [END eventhub_client_sender_close]


def test_example_eventhub_receiver_ops(live_eventhub_config, connection_str):
    from azure.eventhub import EventHubClient
    from azure.eventhub import EventPosition

    # [START eventhub_client_receiver_close]
    client = EventHubClient.from_connection_string(connection_str)
    receiver = client.create_receiver(partition_id="0", consumer_group="$default", event_position=EventPosition('@latest'))
    try:
        receiver.receive(timeout=1)
    finally:
        # Close down the receive handler.
        receiver.close()
    # [END eventhub_client_receiver_close]
