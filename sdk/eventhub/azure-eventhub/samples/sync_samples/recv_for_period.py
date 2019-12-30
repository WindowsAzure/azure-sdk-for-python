#!/usr/bin/env python

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
An example to show receiving events from an Event Hub for a period of time.
"""
import os
import threading
import time
from azure.eventhub import EventHubConsumerClient

CONNECTION_STR = os.environ["EVENT_HUB_CONN_STR"]
EVENTHUB_NAME = os.environ['EVENT_HUB_NAME']


def on_event(partition_context, event):
    # put your code here
    print("Received event from partition: {}".format(partition_context.partition_id))


def on_partition_initialize(partition_context):
    # put your code here
    print("Partition: {} has been initialized".format(partition_context.partition_id))


def on_partition_close(partition_context, reason):
    # put your code here
    print("Partition: {} has been closed, reason for closing: {}".format(partition_context.partition_id,
                                                                         reason))


def on_error(partition_context, error):
    # put your code here
    print("Partition: {} met an exception during receiving: {}".format(partition_context.partition_id,
                                                                       error))


if __name__ == '__main__':
    consumer_client = EventHubConsumerClient.from_connection_string(
        conn_str=CONNECTION_STR,
        consumer_group='$Default',
        eventhub_name=EVENTHUB_NAME,
    )

    duration = 15
    print('Consumer will keep receiving for {} seconds, start time is {}'.format(duration, time.time()))

    try:
        thread = threading.Thread(
            target=consumer_client.receive,
            kwargs={
                "on_event": on_event,
                "on_partition_initialize": on_partition_initialize,
                "on_partition_close": on_partition_close,
                "on_error": on_error
            },
            daemon=True
        )
        thread.start()
        time.sleep(duration)
        consumer_client.close()
        thread.join()
    except KeyboardInterrupt:
        print('Stop receiving.')

    print('Consumer has stopped receiving, end time is {}'.format(time.time()))
