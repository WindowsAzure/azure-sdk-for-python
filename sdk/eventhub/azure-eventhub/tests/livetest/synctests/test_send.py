# -- coding: utf-8 --
#-------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#--------------------------------------------------------------------------

import pytest
import time
import json
import sys

from uamqp import constants as uamqp_constants

from azure.eventhub import EventData, TransportType, EventDataBatch, PartitionPublishingConfiguration
from azure.eventhub import EventHubProducerClient
from azure.eventhub.exceptions import EventDataSendError, ConnectionLostError

@pytest.mark.liveTest
def test_send_with_partition_key(connstr_receivers):
    connection_str, receivers = connstr_receivers
    client = EventHubProducerClient.from_connection_string(connection_str)
    with client:
        data_val = 0
        for partition in [b"a", b"b", b"c", b"d", b"e", b"f"]:
            partition_key = b"test_partition_" + partition
            for i in range(50):
                batch = client.create_batch(partition_key=partition_key)
                batch.add(EventData(str(data_val)))
                data_val += 1
                client.send_batch(batch)

        client.send_batch(client.create_batch())

    found_partition_keys = {}
    for index, partition in enumerate(receivers):
        received = partition.receive_message_batch(timeout=5000)
        for message in received:
            try:
                event_data = EventData._from_message(message)
                existing = found_partition_keys[event_data.partition_key]
                assert existing == index
            except KeyError:
                found_partition_keys[event_data.partition_key] = index


@pytest.mark.liveTest
def test_send_and_receive_large_body_size(connstr_receivers):
    if sys.platform.startswith('darwin'):
        pytest.skip("Skipping on OSX - open issue regarding message size")
    connection_str, receivers = connstr_receivers
    client = EventHubProducerClient.from_connection_string(connection_str)
    with client:
        payload = 250 * 1024
        batch = client.create_batch()
        batch.add(EventData("A" * payload))
        client.send_batch(batch)

    received = []
    for r in receivers:
        received.extend([EventData._from_message(x) for x in r.receive_message_batch(timeout=10000)])

    assert len(received) == 1
    assert len(list(received[0].body)[0]) == payload


@pytest.mark.parametrize("payload",
                         [b"", b"A single event"])
@pytest.mark.liveTest
def test_send_and_receive_small_body(connstr_receivers, payload):
    connection_str, receivers = connstr_receivers
    client = EventHubProducerClient.from_connection_string(connection_str)
    with client:
        batch = client.create_batch()
        batch.add(EventData(payload))
        client.send_batch(batch)
    received = []
    for r in receivers:
        received.extend([EventData._from_message(x) for x in r.receive_message_batch(timeout=5000)])

    assert len(received) == 1
    assert list(received[0].body)[0] == payload


@pytest.mark.liveTest
def test_send_partition(connstr_receivers):
    connection_str, receivers = connstr_receivers
    client = EventHubProducerClient.from_connection_string(connection_str)
    with client:
        batch = client.create_batch(partition_id="1")
        batch.add(EventData(b"Data"))
        client.send_batch(batch)

    partition_0 = receivers[0].receive_message_batch(timeout=5000)
    assert len(partition_0) == 0
    partition_1 = receivers[1].receive_message_batch(timeout=5000)
    assert len(partition_1) == 1


@pytest.mark.liveTest
def test_send_non_ascii(connstr_receivers):
    connection_str, receivers = connstr_receivers
    client = EventHubProducerClient.from_connection_string(connection_str)
    with client:
        batch = client.create_batch(partition_id="0")
        batch.add(EventData(u"é,è,à,ù,â,ê,î,ô,û"))
        batch.add(EventData(json.dumps({"foo": u"漢字"})))
        client.send_batch(batch)
    time.sleep(1)
    # receive_message_batch() returns immediately once it receives any messages before the max_batch_size
    # and timeout reach. Could be 1, 2, or any number between 1 and max_batch_size.
    # So call it twice to ensure the two events are received.
    partition_0 = [EventData._from_message(x) for x in receivers[0].receive_message_batch(timeout=5000)] + \
                  [EventData._from_message(x) for x in receivers[0].receive_message_batch(timeout=5000)]
    assert len(partition_0) == 2
    assert partition_0[0].body_as_str() == u"é,è,à,ù,â,ê,î,ô,û"
    assert partition_0[1].body_as_json() == {"foo": u"漢字"}


@pytest.mark.liveTest
def test_send_multiple_partitions_with_app_prop(connstr_receivers):
    connection_str, receivers = connstr_receivers
    app_prop_key = "raw_prop"
    app_prop_value = "raw_value"
    app_prop = {app_prop_key: app_prop_value}
    client = EventHubProducerClient.from_connection_string(connection_str)
    with client:
        ed0 = EventData(b"Message 0")
        ed0.properties = app_prop
        batch = client.create_batch(partition_id="0")
        batch.add(ed0)
        client.send_batch(batch)

        ed1 = EventData(b"Message 1")
        ed1.properties = app_prop
        batch = client.create_batch(partition_id="1")
        batch.add(ed1)
        client.send_batch(batch)

    partition_0 = [EventData._from_message(x) for x in receivers[0].receive_message_batch(timeout=5000)]
    assert len(partition_0) == 1
    assert partition_0[0].properties[b"raw_prop"] == b"raw_value"
    partition_1 = [EventData._from_message(x) for x in receivers[1].receive_message_batch(timeout=5000)]
    assert len(partition_1) == 1
    assert partition_1[0].properties[b"raw_prop"] == b"raw_value"


@pytest.mark.liveTest
def test_send_over_websocket_sync(connstr_receivers):
    connection_str, receivers = connstr_receivers
    client = EventHubProducerClient.from_connection_string(connection_str, transport_type=TransportType.AmqpOverWebsocket)

    with client:
        batch = client.create_batch(partition_id="0")
        batch.add(EventData("Event Data"))
        client.send_batch(batch)

    time.sleep(1)
    received = []
    received.extend(receivers[0].receive_message_batch(max_batch_size=5, timeout=10000))
    assert len(received) == 1


@pytest.mark.liveTest
def test_send_with_create_event_batch_with_app_prop_sync(connstr_receivers):
    connection_str, receivers = connstr_receivers
    app_prop_key = "raw_prop"
    app_prop_value = "raw_value"
    app_prop = {app_prop_key: app_prop_value}
    client = EventHubProducerClient.from_connection_string(connection_str, transport_type=TransportType.AmqpOverWebsocket)
    with client:
        event_data_batch = client.create_batch(max_size_in_bytes=100000)
        while True:
            try:
                ed = EventData('A single event data')
                ed.properties = app_prop
                event_data_batch.add(ed)
            except ValueError:
                break
        client.send_batch(event_data_batch)
        received = []
        for r in receivers:
            received.extend(r.receive_message_batch(timeout=5000))
        assert len(received) >= 1
        assert EventData._from_message(received[0]).properties[b"raw_prop"] == b"raw_value"


@pytest.mark.liveTest
def test_send_list(connstr_receivers):
    connection_str, receivers = connstr_receivers
    client = EventHubProducerClient.from_connection_string(connection_str)
    payload = "A1"
    with client:
        client.send_batch([EventData(payload)])
    received = []
    for r in receivers:
        received.extend([EventData._from_message(x) for x in r.receive_message_batch(timeout=10000)])

    assert len(received) == 1
    assert received[0].body_as_str() == payload


@pytest.mark.liveTest
def test_send_list_partition(connstr_receivers):
    connection_str, receivers = connstr_receivers
    client = EventHubProducerClient.from_connection_string(connection_str)
    payload = "A1"
    with client:
        client.send_batch([EventData(payload)], partition_id="0")
        message = receivers[0].receive_message_batch(timeout=10000)[0]
        received = EventData._from_message(message)
    assert received.body_as_str() == payload


@pytest.mark.parametrize("to_send, exception_type",
                         [([EventData("A"*1024)]*1100, ValueError),
                          ("any str", AttributeError)
                          ])
@pytest.mark.liveTest
def test_send_list_wrong_data(connection_str, to_send, exception_type):
    client = EventHubProducerClient.from_connection_string(connection_str)
    with client:
        with pytest.raises(exception_type):
            client.send_batch(to_send)


@pytest.mark.parametrize("partition_id, partition_key", [("0", None), (None, "pk")])
def test_send_batch_pid_pk(invalid_hostname, partition_id, partition_key):
    # Use invalid_hostname because this is not a live test.
    client = EventHubProducerClient.from_connection_string(invalid_hostname)
    batch = EventDataBatch(partition_id=partition_id, partition_key=partition_key)
    with client:
        with pytest.raises(TypeError):
            client.send_batch(batch, partition_id=partition_id, partition_key=partition_key)


@pytest.mark.liveTest
def test_idempotent_sender(connstr_receivers):
    connection_str, receivers = connstr_receivers
    client = EventHubProducerClient.from_connection_string(connection_str, enable_idempotent_partitions=True)
    payload = "A1"
    with client:

        with pytest.raises(ValueError):
            client.send_batch([EventData(payload)], partition_key="key")

        with pytest.raises(ValueError):
            client.send_batch([EventData(payload)])

        with pytest.raises(ValueError):
            client.create_batch()

        with pytest.raises(ValueError):
            client.create_batch(partition_key="key")

        partition_publishing_properties = client.get_partition_publishing_properties("0")
        assert partition_publishing_properties["enable_idempotent_publishing"]
        assert partition_publishing_properties["partition_id"] == "0"
        assert partition_publishing_properties["last_published_sequence_number"] is None
        assert partition_publishing_properties["producer_group_id"] is None
        assert partition_publishing_properties["owner_level"] is None

        event_data_batch = client.create_batch(partition_id="0")
        event_data = EventData(payload)
        event_data_batch.add(event_data)
        client.send_batch(event_data_batch)

        with pytest.raises(ValueError):
            # published event_data_batch could not be published again
            client.send_batch(event_data_batch)

        partition_publishing_properties = client.get_partition_publishing_properties("0")
        assert partition_publishing_properties["last_published_sequence_number"] == 0
        assert partition_publishing_properties["producer_group_id"] is not None
        assert partition_publishing_properties["owner_level"] is not None
        assert event_data_batch.starting_published_sequence_number == 0
        assert event_data.published_sequence_number == 0

        message = receivers[0].receive_message_batch(timeout=10000)[0]
        received = EventData._from_message(message)
        assert received.body_as_str() == payload

        event_data_list = [EventData(payload), EventData(payload)]
        client.send_batch(event_data_list, partition_id="0")

        partition_publishing_properties = client.get_partition_publishing_properties("0")
        assert partition_publishing_properties["last_published_sequence_number"] == 2
        assert event_data_list[0].published_sequence_number == 1
        assert event_data_list[1].published_sequence_number == 2
        message = receivers[0].receive_message_batch(timeout=10000)
        assert len(message) == 2


@pytest.mark.liveTest
def test_idempotent_sender_partition_configs(connstr_receivers):
    connection_str, receivers = connstr_receivers

    client = EventHubProducerClient.from_connection_string(
        connection_str,
        enable_idempotent_partitions=True,
    )

    payload = "A1"
    event_data_batch = client.create_batch(partition_id="0")
    event_data = EventData(payload)
    event_data_batch.add(event_data)
    client.send_batch(event_data_batch)

    partition_publishing_properties = client.get_partition_publishing_properties("0")
    assert partition_publishing_properties["last_published_sequence_number"] is not None
    assert partition_publishing_properties["producer_group_id"] is not None
    assert partition_publishing_properties["owner_level"] is not None
    assert event_data_batch.starting_published_sequence_number == 0
    assert event_data.published_sequence_number == 0

    partition_config_for_producer_2 = {
        "0": PartitionPublishingConfiguration(
            producer_group_id=partition_publishing_properties["producer_group_id"],
            owner_level=partition_publishing_properties["owner_level"] + 1
        )
    }

    client_2 = EventHubProducerClient.from_connection_string(
        connection_str,
        enable_idempotent_partitions=True,
        partition_configs=partition_config_for_producer_2
    )
    event_data_list = [EventData(payload), EventData(payload)]
    client_2.send_batch(event_data_list, partition_id="0")
    partition_publishing_properties_2 = client_2.get_partition_publishing_properties("0")
    # with the new owner_level, the sequence number starts from 0 again
    assert partition_publishing_properties_2["last_published_sequence_number"] == 1
    assert partition_publishing_properties_2["producer_group_id"] == partition_publishing_properties["producer_group_id"]
    assert partition_publishing_properties_2["owner_level"] == partition_publishing_properties["owner_level"] + 1

    # test producer-epoch-stolen
    with pytest.raises(EventDataSendError):
        # the first producer will get exploded as the link is stolen by the second producer with higher owner level
        try:
            client.send_batch([EventData(payload)], partition_id="0")
        except EventDataSendError as e:
            assert e.error == "producer-epoch-stolen"
            raise e

    client.close()
    client_2.close()


@pytest.mark.liveTest
def test_idempotent_sender_wrong_partition_configs(connstr_receivers):
    connection_str, receivers = connstr_receivers
    payload = "A1"
    with pytest.raises(ValueError):
        PartitionPublishingConfiguration(owner_level=2**15)

    with pytest.raises(ValueError):
        PartitionPublishingConfiguration(producer_group_id=-1)

    with pytest.raises(ValueError):
        EventHubProducerClient.from_connection_string(
            connection_str,
            enable_idempotent_partitions=True,
            partition_configs={"0": {"starting_sequence_number": 2**31}}
        )

    partition_configs = {
        "0": {
            "producer_group_id": 100,
            "owner_level": 100,
            "starting_sequence_number": 100
        }
    }
    client = EventHubProducerClient.from_connection_string(
        connection_str,
        enable_idempotent_partitions=True,
        partition_configs=partition_configs
    )

    # test invalid init setting
    with pytest.raises(ConnectionLostError):
        try:
            # The service would return link detach with error code being "not allowed"
            client.send_batch([EventData(payload)], partition_id="0")
            client.close()
        except ConnectionLostError as e:
            assert e.details.condition == uamqp_constants.ErrorCodes.NotAllowed
            raise e

    client = EventHubProducerClient.from_connection_string(
        connection_str,
        enable_idempotent_partitions=True
    )

    event_data_list = [EventData(payload) for _ in range(10)]
    client.send_batch(event_data_list, partition_id="0")

    partition_publishing_properties = client.get_partition_publishing_properties("0")

    # test out-of-sequence
    partition_config_for_producer_2 = {
        "0": {
            "producer_group_id": partition_publishing_properties["producer_group_id"],
            "owner_level": partition_publishing_properties["owner_level"],
            "starting_sequence_number": partition_publishing_properties["last_published_sequence_number"] - 5
        }
    }

    client_2 = EventHubProducerClient.from_connection_string(
        connection_str,
        enable_idempotent_partitions=True,
        partition_configs=partition_config_for_producer_2
    )
    with pytest.raises(EventDataSendError):
        try:
            client_2.send_batch([EventData(payload)], partition_id="0")
        except EventDataSendError as e:
            assert e.error == "out-of-order-sequence"
            raise e

    client.close()
    client_2.close()
