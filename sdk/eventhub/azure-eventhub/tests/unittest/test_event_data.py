import platform
import pytest
import pickle
import uamqp
from packaging import version
from azure.eventhub import _common

pytestmark = pytest.mark.skipif(platform.python_implementation() == "PyPy", reason="This is ignored for PyPy")


from azure.eventhub import EventData, EventDataBatch


@pytest.mark.parametrize("test_input, expected_result",
                         [("", ""), ("AAA", "AAA"), (None, ValueError), (["a", "b", "c"], "abc"), (b"abc", "abc")])
def test_constructor(test_input, expected_result):
    if isinstance(expected_result, type):
        with pytest.raises(expected_result):
            EventData(test_input)
    else:
        event_data = EventData(test_input)
        assert event_data.body_as_str() == expected_result
        assert event_data.partition_key is None
        assert len(event_data.properties) == 0
        assert event_data.enqueued_time is None
        assert event_data.offset is None
        assert event_data.sequence_number is None
        assert len(event_data.system_properties) == 0
        assert str(event_data) == "{{ body: '{}', properties: {{}} }}".format(expected_result)
        assert repr(event_data) == "EventData(body='{}', properties={{}}, offset=None, sequence_number=None, partition_key=None, enqueued_time=None)".format(expected_result)
        with pytest.raises(TypeError):
            event_data.body_as_json()


def test_body_json():
    event_data = EventData('{"a":"b"}')
    assert str(event_data) == "{ body: '{\"a\":\"b\"}', properties: {} }"
    assert repr(event_data) == "EventData(body='{\"a\":\"b\"}', properties={}, offset=None, sequence_number=None, partition_key=None, enqueued_time=None)"
    jo = event_data.body_as_json()
    assert jo["a"] == "b"


def test_body_wrong_json():
    event_data = EventData('aaa')
    with pytest.raises(TypeError):
        event_data.body_as_json()


def test_app_properties():
    app_props = {"a": "b"}
    event_data = EventData("")
    event_data.properties = app_props
    assert str(event_data) == "{ body: '', properties: {'a': 'b'} }"
    assert repr(event_data) == "EventData(body='', properties={'a': 'b'}, offset=None, sequence_number=None, partition_key=None, enqueued_time=None)"
    assert event_data.properties["a"] == "b"


def test_sys_properties():
    properties = uamqp.message.MessageProperties()
    properties.message_id = "message_id"
    properties.user_id = "user_id"
    properties.to = "to"
    properties.subject = "subject"
    properties.reply_to = "reply_to"
    properties.correlation_id = "correlation_id"
    properties.content_type = "content_type"
    properties.content_encoding = "content_encoding"
    properties.absolute_expiry_time = 1
    properties.creation_time = 1
    properties.group_id = "group_id"
    properties.group_sequence = 1
    properties.reply_to_group_id = "reply_to_group_id"
    message = uamqp.Message(properties=properties)
    message.annotations = {_common.PROP_OFFSET: "@latest"}
    ed = EventData._from_message(message)  # type: EventData

    assert ed.system_properties[_common.PROP_OFFSET] == "@latest"
    assert ed.system_properties[_common.PROP_CORRELATION_ID] == properties.correlation_id
    assert ed.system_properties[_common.PROP_MESSAGE_ID] == properties.message_id
    assert ed.system_properties[_common.PROP_CONTENT_ENCODING] == properties.content_encoding
    assert ed.system_properties[_common.PROP_CONTENT_TYPE] == properties.content_type
    assert ed.system_properties[_common.PROP_USER_ID] == properties.user_id
    assert ed.system_properties[_common.PROP_TO] == properties.to
    assert ed.system_properties[_common.PROP_SUBJECT] == properties.subject
    assert ed.system_properties[_common.PROP_REPLY_TO] == properties.reply_to
    assert ed.system_properties[_common.PROP_ABSOLUTE_EXPIRY_TIME] == properties.absolute_expiry_time
    assert ed.system_properties[_common.PROP_CREATION_TIME] == properties.creation_time
    assert ed.system_properties[_common.PROP_GROUP_ID] == properties.group_id
    assert ed.system_properties[_common.PROP_GROUP_SEQUENCE] == properties.group_sequence
    assert ed.system_properties[_common.PROP_REPLY_TO_GROUP_ID] == properties.reply_to_group_id


def test_event_data_batch():
    batch = EventDataBatch(max_size_in_bytes=100, partition_key="par")
    batch.add(EventData("A"))
    assert str(batch) == "EventDataBatch(max_size_in_bytes=100, partition_id=None, partition_key='par', event_count=1)"
    assert repr(batch) == "EventDataBatch(max_size_in_bytes=100, partition_id=None, partition_key='par', event_count=1)"

    # In uamqp v1.2.8, the encoding size of a message has changed. delivery_count in message header is now set to 0
    # instead of None according to the C spec.
    # This uamqp change is transparent to EH users so it's not considered as a breaking change. However, it's breaking
    # the unit test here. The solution is to add backward compatibility in test.
    if version.parse(uamqp.__version__) >= version.parse("1.2.8"):
        assert batch.size_in_bytes == 97 and len(batch) == 1
    else:
        assert batch.size_in_bytes == 89 and len(batch) == 1
    with pytest.raises(ValueError):
        batch.add(EventData("A"))

@pytest.mark.parametrize("test_input, expected_result",
                         [("", ""), ("AAA", "AAA"), (None, ValueError), (["a", "b", "c"], "abc"), (b"abc", "abc")])
def test_pickle_event_data(test_input, expected_result):
    if isinstance(expected_result, type):
        with pytest.raises(expected_result):
            EventData(test_input)
    else:
        event_data = EventData(test_input)
        pickled_event_data = pickle.loads(pickle.dumps(event_data))
        repickled_event_data = pickle.loads(pickle.dumps(pickled_event_data))
        # check that, even if test_input is changed, pickled_event_data doesn't change
        event_data.properties["a"] = "b"
        assert len(event_data.properties) == 1

        # check that repickled event data produces expected result
        assert repickled_event_data.body_as_str() == expected_result
        assert repickled_event_data.partition_key is None
        assert len(repickled_event_data.properties) == 0
        assert repickled_event_data.enqueued_time is None
        assert repickled_event_data.offset is None
        assert repickled_event_data.sequence_number is None
        assert len(repickled_event_data.system_properties) == 0
        assert str(repickled_event_data) == "{{ body: '{}', properties: {{}} }}".format(expected_result)
        assert repr(repickled_event_data) == "EventData(body='{}', properties={{}}, offset=None, sequence_number=None, partition_key=None, enqueued_time=None)".format(expected_result)

        with pytest.raises(TypeError):
            pickled_event_data.body_as_json()


def test_pickle_body_json():
    event_data = EventData('{"a":"b"}')
    pickled_event_data = pickle.loads(pickle.dumps(event_data))
    assert str(pickled_event_data) == "{ body: '{\"a\":\"b\"}', properties: {} }"
    assert repr(pickled_event_data) == "EventData(body='{\"a\":\"b\"}', properties={}, offset=None, sequence_number=None, partition_key=None, enqueued_time=None)"
    jo = pickled_event_data.body_as_json()
    assert jo["a"] == "b"


def test_pickle_app_properties():
    app_props = {"a": "b"}
    event_data = EventData("")
    event_data.properties = app_props
    pickled_event_data = pickle.loads(pickle.dumps(event_data))
    assert str(pickled_event_data) == "{ body: '', properties: {'a': 'b'} }"
    assert repr(pickled_event_data) == "EventData(body='', properties={'a': 'b'}, offset=None, sequence_number=None, partition_key=None, enqueued_time=None)"
    assert pickled_event_data.properties["a"] == "b"

def test_pickled_twice_sys_properties():
    properties = uamqp.message.MessageProperties()
    properties.message_id = "message_id"
    properties.user_id = "user_id"
    properties.to = "to"
    properties.subject = "subject"
    properties.reply_to = "reply_to"
    properties.correlation_id = "correlation_id"
    properties.content_type = "content_type"
    properties.content_encoding = "content_encoding"
    properties.absolute_expiry_time = 1
    properties.creation_time = 1
    properties.group_id = "group_id"
    properties.group_sequence = 1
    properties.reply_to_group_id = "reply_to_group_id"
    message = uamqp.Message(properties=properties)
    message.annotations = {_common.PROP_OFFSET: "@latest"}
    ed = EventData._from_message(message)  # type: EventData
    pickle_ed = pickle.loads(pickle.dumps(ed))
    repickle_ed = pickle.loads(pickle.dumps(pickle_ed))

    assert repickle_ed.system_properties[_common.PROP_OFFSET] == "@latest"
    assert repickle_ed.system_properties[_common.PROP_CORRELATION_ID] == properties.correlation_id
    assert repickle_ed.system_properties[_common.PROP_MESSAGE_ID] == properties.message_id
    assert repickle_ed.system_properties[_common.PROP_CONTENT_ENCODING] == properties.content_encoding
    assert repickle_ed.system_properties[_common.PROP_CONTENT_TYPE] == properties.content_type
    assert repickle_ed.system_properties[_common.PROP_USER_ID] == properties.user_id
    assert repickle_ed.system_properties[_common.PROP_TO] == properties.to
    assert repickle_ed.system_properties[_common.PROP_SUBJECT] == properties.subject
    assert repickle_ed.system_properties[_common.PROP_REPLY_TO] == properties.reply_to
    assert repickle_ed.system_properties[_common.PROP_ABSOLUTE_EXPIRY_TIME] == properties.absolute_expiry_time
    assert repickle_ed.system_properties[_common.PROP_CREATION_TIME] == properties.creation_time
    assert repickle_ed.system_properties[_common.PROP_GROUP_ID] == properties.group_id
    assert repickle_ed.system_properties[_common.PROP_GROUP_SEQUENCE] == properties.group_sequence
    assert repickle_ed.system_properties[_common.PROP_REPLY_TO_GROUP_ID] == properties.reply_to_group_id
