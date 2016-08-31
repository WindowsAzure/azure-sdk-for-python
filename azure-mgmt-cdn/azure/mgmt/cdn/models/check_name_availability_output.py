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


class CheckNameAvailabilityOutput(Model):
    """Output of check name availability API.

    :param name_available: Indicates whether the name is available.
    :type name_available: bool
    :param reason: The reason why the name is not available.
    :type reason: str
    :param message: The detailed error message describing why the name is not
     available.
    :type message: str
    """ 

    _attribute_map = {
        'name_available': {'key': 'NameAvailable', 'type': 'bool'},
        'reason': {'key': 'Reason', 'type': 'str'},
        'message': {'key': 'Message', 'type': 'str'},
    }

    def __init__(self, name_available=None, reason=None, message=None):
        self.name_available = name_available
        self.reason = reason
        self.message = message
