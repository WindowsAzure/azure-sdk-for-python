# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .copy_sink import CopySink


class AzureQueueSink(CopySink):
    """A copy activity Azure Queue sink.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param write_batch_size: Write batch size. Type: integer (or Expression
     with resultType integer), minimum: 0.
    :type write_batch_size: object
    :param write_batch_timeout: Write batch timeout. Type: string (or
     Expression with resultType string), pattern:
     ((\\d+)\\.)?(\\d\\d):(60|([0-5][0-9])):(60|([0-5][0-9])).
    :type write_batch_timeout: object
    :param sink_retry_count: Sink retry count. Type: integer (or Expression
     with resultType integer).
    :type sink_retry_count: object
    :param sink_retry_wait: Sink retry wait. Type: string (or Expression with
     resultType string), pattern:
     ((\\d+)\\.)?(\\d\\d):(60|([0-5][0-9])):(60|([0-5][0-9])).
    :type sink_retry_wait: object
    :param type: Constant filled by server.
    :type type: str
    """

    _validation = {
        'type': {'required': True},
    }

    def __init__(self, additional_properties=None, write_batch_size=None, write_batch_timeout=None, sink_retry_count=None, sink_retry_wait=None):
        super(AzureQueueSink, self).__init__(additional_properties=additional_properties, write_batch_size=write_batch_size, write_batch_timeout=write_batch_timeout, sink_retry_count=sink_retry_count, sink_retry_wait=sink_retry_wait)
        self.type = 'AzureQueueSink'
