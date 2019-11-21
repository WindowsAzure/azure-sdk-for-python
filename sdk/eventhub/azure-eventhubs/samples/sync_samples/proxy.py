#!/usr/bin/env python

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
An example to show sending and receiving events behind a proxy
"""
import os
import time
from azure.eventhub import EventPosition, EventData, EventHubConsumerClient, EventHubProducerClient

CONNECTION_STR = os.environ["EVENT_HUB_CONN_STR"]
EVENTHUB_NAME = os.environ['EVENT_HUB_NAME']

EVENT_POSITION = EventPosition("-1")
PARTITION = "0"
HTTP_PROXY = {
    'proxy_hostname': '127.0.0.1',  # proxy hostname
    'proxy_port': 3128,  # proxy port
    'username': 'admin',  # username used for proxy authentication if needed
    'password': '123456'  # password used for proxy authentication if needed
}


def on_event(partition_context, event):
    print("received event from partition: {}".format(partition_context.partition_id))
    # do some operations on the event
    print(event)


consumer_client = EventHubConsumerClient.from_connection_string(
    conn_str=CONNECTION_STR, eventhub_name=EVENTHUB_NAME, http_proxy=HTTP_PROXY)
producer_client = EventHubProducerClient.from_connection_string(
    conn_str=CONNECTION_STR, eventhub_name=EVENTHUB_NAME, http_proxy=HTTP_PROXY)

with producer_client:
    producer_client.send(EventData("A single event"))
    print('Finish sending.')

with consumer_client:
    receiving_time = 5
    consumer_client.receive(on_event=on_event, consumer_group='$Default')
    print('Finish receiving.')

