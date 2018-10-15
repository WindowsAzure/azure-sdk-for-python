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


class NotificationSettingsFragment(Model):
    """Notification settings for a schedule.

    :param status: If notifications are enabled for this schedule (i.e.
     Enabled, Disabled). Possible values include: 'Disabled', 'Enabled'
    :type status: str or ~azure.mgmt.devtestlabs.models.NotificationStatus
    :param time_in_minutes: Time in minutes before event at which notification
     will be sent.
    :type time_in_minutes: int
    :param webhook_url: The webhook URL to which the notification will be
     sent.
    :type webhook_url: str
    """

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'time_in_minutes': {'key': 'timeInMinutes', 'type': 'int'},
        'webhook_url': {'key': 'webhookUrl', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(NotificationSettingsFragment, self).__init__(**kwargs)
        self.status = kwargs.get('status', None)
        self.time_in_minutes = kwargs.get('time_in_minutes', None)
        self.webhook_url = kwargs.get('webhook_url', None)
