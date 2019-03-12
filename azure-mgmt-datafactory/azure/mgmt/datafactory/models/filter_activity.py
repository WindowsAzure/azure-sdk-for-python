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


class FilterActivity(ControlActivity):
    """Filter and return results from input array based on the conditions.

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
    :param items: Input array on which filter should be applied.
    :type items: ~azure.mgmt.datafactory.models.Expression
    :param condition: Condition to be used for filtering the input.
    :type condition: ~azure.mgmt.datafactory.models.Expression
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
        'items': {'required': True},
        'condition': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'depends_on': {'key': 'dependsOn', 'type': '[ActivityDependency]'},
        'type': {'key': 'type', 'type': 'str'},
        'items': {'key': 'typeProperties.items', 'type': 'Expression'},
        'condition': {'key': 'typeProperties.condition', 'type': 'Expression'},
    }

    def __init__(self, name, items, condition, additional_properties=None, description=None, depends_on=None):
        super(FilterActivity, self).__init__(additional_properties=additional_properties, name=name, description=description, depends_on=depends_on)
        self.items = items
        self.condition = condition
        self.type = 'Filter'
