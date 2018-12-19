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


class AlertModificationProperties(Model):
    """Properties of the alert modification item.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar alert_id: Unique Id of the alert for which the history is being
     retrieved
    :vartype alert_id: str
    :param modifications: Modification details
    :type modifications:
     list[~azure.mgmt.alertsmanagement.models.AlertModificationItem]
    """

    _validation = {
        'alert_id': {'readonly': True},
    }

    _attribute_map = {
        'alert_id': {'key': 'alertId', 'type': 'str'},
        'modifications': {'key': 'modifications', 'type': '[AlertModificationItem]'},
    }

    def __init__(self, **kwargs):
        super(AlertModificationProperties, self).__init__(**kwargs)
        self.alert_id = None
        self.modifications = kwargs.get('modifications', None)
