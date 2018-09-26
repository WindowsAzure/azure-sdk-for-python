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


class NotificationPreference(Model):
    """Notification preference for a job stage.

    All required parameters must be populated in order to send to Azure.

    :param stage_name: Required. Name of the stage. Possible values include:
     'DevicePrepared', 'Dispatched', 'Delivered', 'PickedUp', 'AtAzureDC',
     'DataCopy'
    :type stage_name: str or ~azure.mgmt.databox.models.NotificationStageName
    :param send_notification: Required. Notification is required or not.
    :type send_notification: bool
    """

    _validation = {
        'stage_name': {'required': True},
        'send_notification': {'required': True},
    }

    _attribute_map = {
        'stage_name': {'key': 'stageName', 'type': 'NotificationStageName'},
        'send_notification': {'key': 'sendNotification', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(NotificationPreference, self).__init__(**kwargs)
        self.stage_name = kwargs.get('stage_name', None)
        self.send_notification = kwargs.get('send_notification', None)
