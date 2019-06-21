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


class ActivityLogAlertActionList(Model):
    """A list of activity log alert actions.

    :param action_groups: The list of activity log alerts.
    :type action_groups:
     list[~azure.mgmt.monitor.v2017_03_01_preview.models.ActivityLogAlertActionGroup]
    """

    _attribute_map = {
        'action_groups': {'key': 'actionGroups', 'type': '[ActivityLogAlertActionGroup]'},
    }

    def __init__(self, *, action_groups=None, **kwargs) -> None:
        super(ActivityLogAlertActionList, self).__init__(**kwargs)
        self.action_groups = action_groups
