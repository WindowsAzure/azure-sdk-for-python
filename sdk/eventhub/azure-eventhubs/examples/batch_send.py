#!/usr/bin/env python

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

"""
An example to show batch sending events to an Event Hub.
"""

# pylint: disable=C0111

import logging
import time
import os

from azure.eventhub import EventData, EventHubClient, EventHubSharedKeyCredential


import examples
logger = examples.get_logger(logging.INFO)

HOSTNAME = os.environ.get('EVENT_HUB_HOSTNAME')  # <mynamespace>.servicebus.windows.net
EVENT_HUB = os.environ.get('EVENT_HUB_NAME')

USER = os.environ.get('EVENT_HUB_SAS_POLICY')
KEY = os.environ.get('EVENT_HUB_SAS_KEY')


try:
    if not HOSTNAME:
        raise ValueError("No EventHubs URL supplied.")

    client = EventHubClient(host=HOSTNAME, event_hub_path=EVENT_HUB, credential=EventHubSharedKeyCredential(USER, KEY), network_tracing=False)
    sender = client.create_sender(partition_id="1")

    list = []
    for i in range(1500):
        list.append('Hello World')

    with sender:
        start_time = time.time()
        data = EventData(body=list)
        sender.send(data)
        end_time = time.time()
        run_time = end_time - start_time
        logger.info("Runtime: {} seconds".format(run_time))

except KeyboardInterrupt:
    pass
