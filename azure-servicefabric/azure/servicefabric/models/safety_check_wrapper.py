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


class SafetyCheckWrapper(Model):
    """A wrapper for the safety check object. Safety checks are performed by
    service fabric before continuing with the operations. These checks ensure
    the availability of the service and the reliability of the state.

    :param safety_check:
    :type safety_check: ~azure.servicefabric.models.SafetyCheck
    """

    _attribute_map = {
        'safety_check': {'key': 'SafetyCheck', 'type': 'SafetyCheck'},
    }

    def __init__(self, safety_check=None):
        super(SafetyCheckWrapper, self).__init__()
        self.safety_check = safety_check
