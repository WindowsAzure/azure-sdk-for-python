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


class ConfigDataProperties(Model):
    """The list of property name/value pairs.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param exclude: Exclude the resource from Advisor evaluations. Valid
     values: False (default) or True.
    :type exclude: bool
    :param low_cpu_threshold: Minimum percentage threshold for Advisor low CPU
     utilization evaluation. Valid only for subscriptions. Valid values: 5
     (default), 10, 15 or 20.
    :type low_cpu_threshold: str
    """

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'exclude': {'key': 'exclude', 'type': 'bool'},
        'low_cpu_threshold': {'key': 'low_cpu_threshold', 'type': 'str'},
    }

    def __init__(self, *, additional_properties=None, exclude: bool=None, low_cpu_threshold: str=None, **kwargs) -> None:
        super(ConfigDataProperties, self).__init__(**kwargs)
        self.additional_properties = additional_properties
        self.exclude = exclude
        self.low_cpu_threshold = low_cpu_threshold
