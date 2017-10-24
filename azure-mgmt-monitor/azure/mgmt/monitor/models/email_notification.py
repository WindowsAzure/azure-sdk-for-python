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


class EmailNotification(Model):
    """Email notification of an autoscale event.

    :param send_to_subscription_administrator: a value indicating whether to
     send email to subscription administrator.
    :type send_to_subscription_administrator: bool
    :param send_to_subscription_co_administrators: a value indicating whether
     to send email to subscription co-administrators.
    :type send_to_subscription_co_administrators: bool
    :param custom_emails: the custom e-mails list. This value can be null or
     empty, in which case this attribute will be ignored.
    :type custom_emails: list[str]
    """

    _attribute_map = {
        'send_to_subscription_administrator': {'key': 'sendToSubscriptionAdministrator', 'type': 'bool'},
        'send_to_subscription_co_administrators': {'key': 'sendToSubscriptionCoAdministrators', 'type': 'bool'},
        'custom_emails': {'key': 'customEmails', 'type': '[str]'},
    }

    def __init__(self, send_to_subscription_administrator=None, send_to_subscription_co_administrators=None, custom_emails=None):
        self.send_to_subscription_administrator = send_to_subscription_administrator
        self.send_to_subscription_co_administrators = send_to_subscription_co_administrators
        self.custom_emails = custom_emails
