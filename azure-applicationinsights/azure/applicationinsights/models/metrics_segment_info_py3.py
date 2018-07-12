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

from msrest.serialization import Model


class MetricsSegmentInfo(Model):
    """A metric segment.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param start: Start time of the metric segment (only when an interval was
     specified).
    :type start: datetime
    :param end: Start time of the metric segment (only when an interval was
     specified).
    :type end: datetime
    :param segments: Segmented metric data (if further segmented).
    :type segments: list[~azure.applicationinsights.models.MetricsSegmentInfo]
    """

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'start': {'key': 'start', 'type': 'iso-8601'},
        'end': {'key': 'end', 'type': 'iso-8601'},
        'segments': {'key': 'segments', 'type': '[MetricsSegmentInfo]'},
    }

    def __init__(self, *, additional_properties=None, start=None, end=None, segments=None, **kwargs) -> None:
        super(MetricsSegmentInfo, self).__init__(**kwargs)
        self.additional_properties = additional_properties
        self.start = start
        self.end = end
        self.segments = segments
