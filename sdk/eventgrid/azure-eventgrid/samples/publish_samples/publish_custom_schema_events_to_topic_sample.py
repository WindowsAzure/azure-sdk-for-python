import sys
import os
import json
from random import randint, sample
from typing import Sequence
import time
import uuid
from msrest.serialization import UTC
import datetime as dt

PACKAGE_PARENT = '..'
SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))

from azure.core.credentials import AzureKeyCredential
from azure.mgmt.eventgrid import EventGridManagementClient
from azure.eventgrid import EventGridPublisherClient
from azure.eventgrid import CustomEvent
from azure.core.exceptions import (
    ResourceNotFoundError,
    ResourceExistsError,
    ClientAuthenticationError
)

key = os.environ["CUSTOM_SCHEMA_ACCESS_KEY"]
topic_hostname = os.environ["CUSTOM_SCHEMA_TOPIC_HOSTNAME"]

# authenticate client
credential = AzureKeyCredential(key)
client = EventGridPublisherClient(topic_hostname, credential)

custom_schema_event = {
    "customSubject": "sample",
    "customEventType": "sample.event",
    "customDataVersion": "2.0",
    "customId": uuid.uuid4(),
    "customEventTime": dt.datetime.now(UTC()).isoformat(),
    "customData": "sample data"
}

# publish events
while True:

    event_list = []     # list of events to publish
    # create events and append to list
    for j in range(randint(1, 3)):
        event = CustomEvent(custom_schema_event)
        event_list.append(event)

    # publish list of events
    client.send(event_list)
    print("Batch of size {} published".format(len(event_list)))
    time.sleep(randint(1, 5))
