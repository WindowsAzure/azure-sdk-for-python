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
    """Description of the check name availability request properties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar message: The detailed info regarding the reason associated with the
     namespace.
    :vartype message: str
    :param name_available: Value indicating namespace is available. Returns
     true if the namespace is available; otherwise, false.
    :type name_available: bool
    :param reason: The reason for unavailability of a namespace. Possible
     values include: 'None', 'InvalidName', 'SubscriptionIsDisabled',
     'NameInUse', 'NameInLockdown', 'TooManyNamespaceInCurrentSubscription'
    :type reason: str or ~azure.mgmt.relay.models.UnavailableReason
    """

    _validation = {
        'message': {'readonly': True},
    }

    _attribute_map = {
        'message': {'key': 'message', 'type': 'str'},
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'UnavailableReason'},
    }

    def __init__(self, name_available=None, reason=None):
        self.message = None
        self.name_available = name_available
        self.reason = reason
