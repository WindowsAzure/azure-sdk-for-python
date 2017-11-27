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

from .control_activity import ControlActivity


class WaitActivity(ControlActivity):
    """This activity suspends pipeline execution for the specified interval.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param name: Activity name.
    :type name: str
    :param description: Activity description.
    :type description: str
    :param depends_on: Activity depends on condition.
    :type depends_on: list[~azure.mgmt.datafactory.models.ActivityDependency]
    :param type: Constant filled by server.
    :type type: str
    :param wait_time_in_seconds: Duration in seconds.
    :type wait_time_in_seconds: int
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
        'wait_time_in_seconds': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'depends_on': {'key': 'dependsOn', 'type': '[ActivityDependency]'},
        'type': {'key': 'type', 'type': 'str'},
        'wait_time_in_seconds': {'key': 'typeProperties.waitTimeInSeconds', 'type': 'int'},
    }

    def __init__(self, name, wait_time_in_seconds, additional_properties=None, description=None, depends_on=None):
        super(WaitActivity, self).__init__(additional_properties=additional_properties, name=name, description=description, depends_on=depends_on)
        self.wait_time_in_seconds = wait_time_in_seconds
        self.type = 'Wait'
