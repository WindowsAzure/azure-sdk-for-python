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


class AlertModificationItem(Model):
    """Alert modification item.

    :param modification_event: Reason for the modification. Possible values
     include: 'AlertCreated', 'StateChange', 'MonitorConditionChange'
    :type modification_event: str or
     ~azure.mgmt.alertsmanagement.models.AlertModificationEvent
    :param old_value: Old value
    :type old_value: str
    :param new_value: New value
    :type new_value: str
    :param modified_at: Modified date and time
    :type modified_at: str
    :param modified_by: Modified user details (Principal client name)
    :type modified_by: str
    :param comments: Modification comments
    :type comments: str
    :param description: Description of the modification
    :type description: str
    """

    _attribute_map = {
        'modification_event': {'key': 'modificationEvent', 'type': 'AlertModificationEvent'},
        'old_value': {'key': 'oldValue', 'type': 'str'},
        'new_value': {'key': 'newValue', 'type': 'str'},
        'modified_at': {'key': 'modifiedAt', 'type': 'str'},
        'modified_by': {'key': 'modifiedBy', 'type': 'str'},
        'comments': {'key': 'comments', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(AlertModificationItem, self).__init__(**kwargs)
        self.modification_event = kwargs.get('modification_event', None)
        self.old_value = kwargs.get('old_value', None)
        self.new_value = kwargs.get('new_value', None)
        self.modified_at = kwargs.get('modified_at', None)
        self.modified_by = kwargs.get('modified_by', None)
        self.comments = kwargs.get('comments', None)
        self.description = kwargs.get('description', None)
