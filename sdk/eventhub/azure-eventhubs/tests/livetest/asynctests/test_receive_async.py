#-------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#--------------------------------------------------------------------------

import asyncio
import pytest
import time

from azure.eventhub import EventData, EventPosition, TransportType, EventHubError
from azure.eventhub.aio import EventHubConsumerClient


@pytest.mark.liveTest
@pytest.mark.asyncio
async def test_receive_end_of_stream_async(connstr_senders):
    async def on_event(partition_context, event):
        if partition_context.partition_id == "0":
            assert event.body_as_str() == "Receiving only a single event"
            assert list(event.body)[0] == b"Receiving only a single event"
            on_event.called = True
    on_event.called = False
    connection_str, senders = connstr_senders
    client = EventHubConsumerClient.from_connection_string(connection_str)
    async with client:
        task = asyncio.ensure_future(client.receive(on_event, "$default", partition_id="0", initial_event_position="-1"))
        await asyncio.sleep(5)
        assert on_event.called is False
        senders[0].send(EventData(b"Receiving only a single event"))
        await asyncio.sleep(5)
        assert on_event.called is True
    task.cancel()


@pytest.mark.parametrize("position, inclusive, expected_result",
                         [("offset", False, "Exclusive"),
                          ("offset", True, "Inclusive"),
                          ("sequence", False, "Exclusive"),
                          ("sequence", True, "Inclusive"),
                          ("enqueued_time", False, "Exclusive")])
@pytest.mark.liveTest
@pytest.mark.asyncio
async def test_receive_with_event_position_async(connstr_senders, position, inclusive, expected_result):
    async def on_event(partition_context, event):
        assert event.last_enqueued_event_properties.get('sequence_number') == event.sequence_number
        assert event.last_enqueued_event_properties.get('offset') == event.offset
        assert event.last_enqueued_event_properties.get('enqueued_time') == event.enqueued_time
        assert event.last_enqueued_event_properties.get('retrieval_time') is not None

        if position == "offset":
            on_event.event_position = event.offset
        elif position == "sequence":
            on_event.event_position = event.sequence_number
        else:
            on_event.event_position = event.enqueued_time
        on_event.event = event

    on_event.event_position = None
    connection_str, senders = connstr_senders
    senders[0].send(EventData(b"Inclusive"))
    client = EventHubConsumerClient.from_connection_string(connection_str)
    async with client:
        task = asyncio.ensure_future(client.receive(on_event, "$default",
                                  initial_event_position="-1",
                                  track_last_enqueued_event_properties=True))
        await asyncio.sleep(5)
        assert on_event.event_position is not None
    task.cancel()
    senders[0].send(EventData(expected_result))
    client2 = EventHubConsumerClient.from_connection_string(connection_str)
    async with client2:
        task = asyncio.ensure_future(
            client2.receive(on_event, "$default",
                            initial_event_position= EventPosition(on_event.event_position, inclusive),
                            track_last_enqueued_event_properties=True))
        await asyncio.sleep(5)
        assert on_event.event.body_as_str() == expected_result
    task.cancel()


@pytest.mark.liveTest
@pytest.mark.asyncio
async def test_receive_owner_level(connstr_senders):
    app_prop = {"raw_prop": "raw_value"}

    async def on_event(partition_context, event):
        pass
    async def on_error(partition_context, error):
        on_error.error = error

    on_error.error = None
    connection_str, senders = connstr_senders
    client1 = EventHubConsumerClient.from_connection_string(connection_str)
    client2 = EventHubConsumerClient.from_connection_string(connection_str)
    try:
        task1 = asyncio.ensure_future(client1.receive(on_event, "$default",
                                                    partition_id="0", initial_event_position="-1",
                                                    on_error=on_error))
        event_list = []
        for i in range(20):
            ed = EventData("Event Number {}".format(i))
            event_list.append(ed)
        senders[0].send(event_list)
        await asyncio.sleep(5)
        task2 = asyncio.ensure_future(client2.receive(on_event, "$default",
                                                    partition_id="0", initial_event_position="-1",
                                                    owner_level=1))
        event_list = []
        for i in range(20):
            ed = EventData("Event Number {}".format(i))
            event_list.append(ed)
        senders[0].send(event_list)
        await asyncio.sleep(5)
        task1.cancel()
        task2.cancel()
    finally:
        await client1.close()
        await client2.close()
    assert isinstance(on_error.error, EventHubError)


@pytest.mark.liveTest
@pytest.mark.asyncio
async def test_receive_over_websocket_async(connstr_senders):
    app_prop = {"raw_prop": "raw_value"}

    async def on_event(partition_context, event):
        on_event.received.append(event)
        on_event.app_prop = event[0].application_properties

    on_event.received = []
    on_event.app_prop = None
    connection_str, senders = connstr_senders
    client = EventHubConsumerClient.from_connection_string(connection_str,
                                                           transport_type=TransportType.AmqpOverWebsocket)

    event_list = []
    for i in range(20):
        ed = EventData("Event Number {}".format(i))
        ed.application_properties = app_prop
        event_list.append(ed)
    senders[0].send(event_list)

    async with client:
        task = asyncio.ensure_future(client.receive(on_event, "$default",
                                  partition_id="0", initial_event_position="-1"))
        await asyncio.sleep(5)
    task.cancel()
    assert len(on_event.received) == 20
    for ed in on_event.received:
        assert ed.application_properties[b"raw_prop"] == b"raw_value"
