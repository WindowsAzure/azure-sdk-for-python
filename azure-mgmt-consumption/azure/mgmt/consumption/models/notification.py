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


class Notification(Model):
    """The notification associated with a budget.

    All required parameters must be populated in order to send to Azure.

    :param enabled: Required. The notification is enabled or not.
    :type enabled: bool
    :param operator: Required. The comparison operator. Possible values
     include: 'EqualTo', 'GreaterThan', 'GreaterThanOrEqualTo'
    :type operator: str or ~azure.mgmt.consumption.models.OperatorType
    :param threshold: Required. Threshold value associated with a
     notification. Notification is sent when the cost exceeded the threshold.
     It is always percent and has to be between 0 and 1000.
    :type threshold: decimal.Decimal
    :param contact_emails: Required. Email addresses to send the budget
     notification to when the threshold is exceeded.
    :type contact_emails: list[str]
    :param contact_roles: Contact roles to send the budget notification to
     when the threshold is exceeded.
    :type contact_roles: list[str]
    :param contact_groups: Action groups to send the budget notification to
     when the threshold is exceeded.
    :type contact_groups: list[str]
    """

    _validation = {
        'enabled': {'required': True},
        'operator': {'required': True},
        'threshold': {'required': True},
        'contact_emails': {'required': True, 'max_items': 50, 'min_items': 1},
        'contact_groups': {'max_items': 50, 'min_items': 0},
    }

    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'operator': {'key': 'operator', 'type': 'str'},
        'threshold': {'key': 'threshold', 'type': 'decimal'},
        'contact_emails': {'key': 'contactEmails', 'type': '[str]'},
        'contact_roles': {'key': 'contactRoles', 'type': '[str]'},
        'contact_groups': {'key': 'contactGroups', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(Notification, self).__init__(**kwargs)
        self.enabled = kwargs.get('enabled', None)
        self.operator = kwargs.get('operator', None)
        self.threshold = kwargs.get('threshold', None)
        self.contact_emails = kwargs.get('contact_emails', None)
        self.contact_roles = kwargs.get('contact_roles', None)
        self.contact_groups = kwargs.get('contact_groups', None)
