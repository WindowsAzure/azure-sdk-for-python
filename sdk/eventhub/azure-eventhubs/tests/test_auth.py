#-------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#--------------------------------------------------------------------------

import pytest
import time

from azure.eventhub import EventData, EventHubClient, EventPosition
from azure.identity import ClientSecretCredential


@pytest.mark.liveTest
def test_client_secret_credential(aad_credential, live_eventhub):
    client_id, secret, tenant_id = aad_credential
    credential = ClientSecretCredential(client_id=client_id, secret=secret, tenant_id=tenant_id)
    client = EventHubClient(host=live_eventhub['hostname'],
                            event_hub_path=live_eventhub['event_hub'],
                            credential=credential,
                            user_agent='customized information')
    sender = client.create_sender(partition_id='0')
    receiver = client.create_receiver(partition_id='0', event_position=EventPosition.new_events_only())

    with receiver:
        received = receiver.receive(timeout=1)
        assert len(received) == 0

        with sender:
            event = EventData(body='A single message')
            sender.send(event)
        time.sleep(1)

        received = receiver.receive(timeout=1)

        assert len(received) == 1
        assert list(received[0].body)[0] == 'A single message'.encode('utf-8')
