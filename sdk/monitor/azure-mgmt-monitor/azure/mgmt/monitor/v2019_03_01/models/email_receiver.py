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


class EmailReceiver(Model):
    """An email receiver.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the email receiver. Names must be
     unique across all receivers within an action group.
    :type name: str
    :param email_address: Required. The email address of this receiver.
    :type email_address: str
    :param use_common_alert_schema: Required. Indicates whether to use common
     alert schema.
    :type use_common_alert_schema: bool
    :ivar status: The receiver status of the e-mail. Possible values include:
     'NotSpecified', 'Enabled', 'Disabled'
    :vartype status: str or
     ~azure.mgmt.monitor.v2019_03_01.models.ReceiverStatus
    """

    _validation = {
        'name': {'required': True},
        'email_address': {'required': True},
        'use_common_alert_schema': {'required': True},
        'status': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'email_address': {'key': 'emailAddress', 'type': 'str'},
        'use_common_alert_schema': {'key': 'useCommonAlertSchema', 'type': 'bool'},
        'status': {'key': 'status', 'type': 'ReceiverStatus'},
    }

    def __init__(self, **kwargs):
        super(EmailReceiver, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.email_address = kwargs.get('email_address', None)
        self.use_common_alert_schema = kwargs.get('use_common_alert_schema', None)
        self.status = None
