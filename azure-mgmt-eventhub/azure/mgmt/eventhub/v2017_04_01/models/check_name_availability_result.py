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


class CheckNameAvailabilityResult(Model):
    """The Result of the CheckNameAvailability operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar message: The detailed info regarding the reason associated with the
     Namespace.
    :vartype message: str
    :param name_available: Value indicating Namespace is availability, true if
     the Namespace is available; otherwise, false.
    :type name_available: bool
    :param reason: The reason for unavailability of a Namespace. Possible
     values include: 'None', 'InvalidName', 'SubscriptionIsDisabled',
     'NameInUse', 'NameInLockdown', 'TooManyNamespaceInCurrentSubscription'
    :type reason: str or
     ~azure.mgmt.eventhub.v2017_04_01.models.UnavailableReason
    """

    _validation = {
        'message': {'readonly': True},
    }

    _attribute_map = {
        'message': {'key': 'message', 'type': 'str'},
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'UnavailableReason'},
    }

    def __init__(self, **kwargs):
        super(CheckNameAvailabilityResult, self).__init__(**kwargs)
        self.message = None
        self.name_available = kwargs.get('name_available', None)
        self.reason = kwargs.get('reason', None)
