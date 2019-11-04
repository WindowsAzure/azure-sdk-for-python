#!/usr/bin/env python

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
An example to show receiving events from an Event Hub partition with EventHubConsumerClient tracking
the last enqueued event properties of specific partition.
"""
import os
import time
from azure.eventhub import EventPosition, EventHubConsumerClient

CONNECTION_STR = os.environ["EVENT_HUB_CONN_STR"]
EVENT_HUB = os.environ['EVENT_HUB_NAME']

RECEIVE_TIMEOUT = 5  # timeout in seconds for a receiving operation. 0 or None means no timeout
RETRY_TOTAL = 3  # max number of retries for receive operations within the receive timeout. Actual number of retries clould be less if RECEIVE_TIMEOUT is too small

EVENT_POSITION = EventPosition("-1")
PARTITION = "0"

total = 0


def do_operation(event):
    # do some operations on the event, avoid time-consuming ops
    pass


def on_event(partition_context, events):
    # put your code here
    global total
    print("received events: {} from partition {}".format(len(events), partition_context.partition_id))
    total += len(events)
    for event in events:
        do_operation(event)

    print("Last enqueued event properties from partition: {} is: {}".
          format(partition_context.partition_id,
                 events[-1].last_enqueued_event_properties))


if __name__ == '__main__':
    consumer_client = EventHubConsumerClient.from_connection_string(
        conn_str=CONNECTION_STR,
        event_hub_path=EVENT_HUB,
        receive_timeout=RECEIVE_TIMEOUT,  # the wait time for single receiving iteration
        retry_total=RETRY_TOTAL  # num of retry times if receiving from EventHub has an error.
    )

    try:
        with consumer_client:
            consumer_client.receive(on_event=on_event, consumer_group='$Default',
                                    partition_id='0', track_last_enqueued_event_properties=True)

    except KeyboardInterrupt:
        print('Stop receiving.')
        consumer_client.close()
