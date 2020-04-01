# ------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# -------------------------------------------------------------------------

from enum import Enum

from uamqp import constants

VENDOR = b"com.microsoft"
DATETIMEOFFSET_EPOCH = 621355968000000000

ENQUEUEDTIMEUTCNAME = b"x-opt-enqueued-time"
SCHEDULEDENQUEUETIMENAME = b"x-opt-scheduled-enqueue-time"
SEQUENCENUBMERNAME = b"x-opt-sequence-number"
LOCKTOKENNAME = b"x-opt-lock-token"
LOCKEDUNTILNAME = b"x-opt-locked-until"
PARTITIONKEYNAME = b"x-opt-partition-key"
DEADLETTERSOURCENAME = b"x-opt-deadletter-source"
DEADLETTERNAME = VENDOR + b":dead-letter"
ASSOCIATEDLINKPROPERTYNAME = b"associated-link-name"

SESSION_FILTER = VENDOR + b":session-filter"
SESSION_LOCKED_UNTIL = VENDOR + b":locked-until-utc"
SESSION_LOCK_LOST = VENDOR + b":session-lock-lost"
SESSION_LOCK_TIMEOUT = VENDOR + b":timeout"

REQUEST_RESPONSE_OPERATION_NAME = b"operation"
REQUEST_RESPONSE_TIMEOUT = VENDOR + b":server-timeout"
REQUEST_RESPONSE_RENEWLOCK_OPERATION = VENDOR + b":renew-lock"
REQUEST_RESPONSE_RENEW_SESSION_LOCK_OPERATION = VENDOR + b":renew-session-lock"
REQUEST_RESPONSE_RECEIVE_BY_SEQUENCE_NUMBER = VENDOR + b":receive-by-sequence-number"
REQUEST_RESPONSE_SCHEDULE_MESSAGE_OPERATION = VENDOR + b":schedule-message"
REQUEST_RESPONSE_CANCEL_SCHEDULED_MESSAGE_OPERATION = VENDOR + b":cancel-scheduled-message"
REQUEST_RESPONSE_PEEK_OPERATION = VENDOR + b":peek-message"
REQUEST_RESPONSE_UPDATE_DISPOSTION_OPERATION = VENDOR + b":update-disposition"
REQUEST_RESPONSE_GET_SESSION_STATE_OPERATION = VENDOR + b":get-session-state"
REQUEST_RESPONSE_SET_SESSION_STATE_OPERATION = VENDOR + b":set-session-state"
REQUEST_RESPONSE_GET_MESSAGE_SESSIONS_OPERATION = VENDOR + b":get-message-sessions"
REQUEST_RESPONSE_ADD_RULE_OPERATION = VENDOR + b":add-rule"
REQUEST_RESPONSE_REMOVE_RULE_OPERATION = VENDOR + b":remove-rule"
REQUEST_RESPONSE_GET_RULES_OPERATION = VENDOR + b":enumerate-rules"

SETTLEMENT_COMPLETE = "completed"
SETTLEMENT_ABANDON = "abandoned"
SETTLEMENT_DEFER = "defered"
SETTLEMENT_DEADLETTER = "suspended"

CONTAINER_PREFIX = "servicebus.pysdk-"
JWT_TOKEN_SCOPE = "https://servicebus.azure.net//.default"
USER_AGENT_PREFIX = "azsdk-python-servicebus"

MANAGEMENT_PATH_SUFFIX = "/$management"

MGMT_RESPONSE_SESSION_STATE = b'session-state'
MGMT_RESPONSE_EXPIRATION = b'expiration'
MGMT_REQUEST_SESSION_ID = 'session-id'
MGMT_REQUEST_SESSION_STATE = 'session-state'
MGMT_REQUEST_DISPOSITION_STATUS = 'disposition-status'
MGMT_REQUEST_LOCK_TOKENS = 'lock-tokens'
MGMT_REQUEST_SEQUENCE_NUMBERS = 'sequence-numbers'
MGMT_REQUEST_RECEIVER_SETTLE_MODE = 'receiver-settle-mode'
MGMT_REQUEST_FROM_SEQUENCE_NUMBER = 'from-sequence-number'
MGMT_REQUEST_MESSAGE_COUNT = 'message-count'
MGMT_REQUEST_MESSAGE = 'message'
MGMT_REQUEST_MESSAGES = 'messages'
MGMT_REQUEST_MESSAGE_ID = 'message-id'
MGMT_REQUEST_PARTITION_KEY = 'partition-key'
MGMT_REQUEST_VIA_PARTITION_KEY = 'via-partition-key'
MGMT_REQUEST_DEAD_LETTER_REASON = 'deadletter-reason'
MGMT_REQUEST_DEAD_LETTER_DESCRIPTION = 'deadletter-description'

MESSAGE_COMPLETE = 'complete'
MESSAGE_DEAD_LETTER = 'dead-letter'
MESSAGE_ABANDON = 'abandon'
MESSAGE_DEFER = 'defer'
MESSAGE_RENEW_LOCK = 'renew'

# event_data.encoded_size < 255, batch encode overhead is 5, >=256, overhead is 8 each
_BATCH_MESSAGE_OVERHEAD_COST = [5, 8]

# Message annotation keys
_X_OPT_ENQUEUED_TIME = b'x-opt-enqueued-time'
_X_OPT_SEQUENCE_NUMBER = b'x-opt-sequence-number'
_X_OPT_ENQUEUE_SEQUENCE_NUMBER = b'x-opt-enqueue-sequence-number'
_X_OPT_PARTITION_ID = b'x-opt-partition-id'
_X_OPT_PARTITION_KEY = b'x-opt-partition-key'
_X_OPT_VIA_PARTITION_KEY = b'x-opt-via-partition-key'
_X_OPT_LOCKED_UNTIL = b'x-opt-locked-until'
_X_OPT_LOCK_TOKEN = b'x-opt-lock-token'
_X_OPT_SCHEDULED_ENQUEUE_TIME = b'x-opt-scheduled-enqueue-time'


class ReceiveSettleMode(Enum):
    PeekLock = constants.ReceiverSettleMode.PeekLock
    ReceiveAndDelete = constants.ReceiverSettleMode.ReceiveAndDelete


class SessionFilter(Enum):
    NextAvailable = 0


NEXT_AVAILABLE = SessionFilter.NextAvailable
