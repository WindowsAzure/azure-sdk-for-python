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


class AS2ErrorSettings(Model):
    """The AS2 agreement error settings.

    :param suspend_duplicate_message: The value indicating whether to suspend
     duplicate message.
    :type suspend_duplicate_message: bool
    :param resend_if_mdn_not_received: The value indicating whether to resend
     message If MDN is not received.
    :type resend_if_mdn_not_received: bool
    """

    _validation = {
        'suspend_duplicate_message': {'required': True},
        'resend_if_mdn_not_received': {'required': True},
    }

    _attribute_map = {
        'suspend_duplicate_message': {'key': 'suspendDuplicateMessage', 'type': 'bool'},
        'resend_if_mdn_not_received': {'key': 'resendIfMdnNotReceived', 'type': 'bool'},
    }

    def __init__(self, suspend_duplicate_message, resend_if_mdn_not_received):
        super(AS2ErrorSettings, self).__init__()
        self.suspend_duplicate_message = suspend_duplicate_message
        self.resend_if_mdn_not_received = resend_if_mdn_not_received
