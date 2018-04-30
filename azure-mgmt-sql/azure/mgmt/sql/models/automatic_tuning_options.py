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


class AutomaticTuningOptions(Model):
    """Automatic tuning properties for individual advisors.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param desired_state: Automatic tuning option desired state. Possible
     values include: 'Off', 'On', 'Default'
    :type desired_state: str or
     ~azure.mgmt.sql.models.AutomaticTuningOptionModeDesired
    :ivar actual_state: Automatic tuning option actual state. Possible values
     include: 'Off', 'On'
    :vartype actual_state: str or
     ~azure.mgmt.sql.models.AutomaticTuningOptionModeActual
    :ivar reason_code: Reason code if desired and actual state are different.
    :vartype reason_code: int
    :ivar reason_desc: Reason description if desired and actual state are
     different. Possible values include: 'Default', 'Disabled',
     'AutoConfigured', 'InheritedFromServer', 'QueryStoreOff',
     'QueryStoreReadOnly', 'NotSupported'
    :vartype reason_desc: str or
     ~azure.mgmt.sql.models.AutomaticTuningDisabledReason
    """

    _validation = {
        'actual_state': {'readonly': True},
        'reason_code': {'readonly': True},
        'reason_desc': {'readonly': True},
    }

    _attribute_map = {
        'desired_state': {'key': 'desiredState', 'type': 'AutomaticTuningOptionModeDesired'},
        'actual_state': {'key': 'actualState', 'type': 'AutomaticTuningOptionModeActual'},
        'reason_code': {'key': 'reasonCode', 'type': 'int'},
        'reason_desc': {'key': 'reasonDesc', 'type': 'AutomaticTuningDisabledReason'},
    }

    def __init__(self, **kwargs):
        super(AutomaticTuningOptions, self).__init__(**kwargs)
        self.desired_state = kwargs.get('desired_state', None)
        self.actual_state = None
        self.reason_code = None
        self.reason_desc = None
