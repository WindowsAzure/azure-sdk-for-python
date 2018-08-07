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

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar is_name_available: A value indicating whether the name is available.
    :vartype is_name_available: bool
    :ivar reason: The reason why the name is not available. 'Invalid'
     indicates the name provided does not match the naming requirements
     (incorrect length, unsupported characters, etc.). 'AlreadyExists'
     indicates that the name is already in use and is therefore unavailable.
     Possible values include: 'Invalid', 'AlreadyExists'
    :vartype reason: str or ~azure.mgmt.search.models.UnavailableNameReason
    :ivar message: A message that explains why the name is invalid and
     provides resource naming requirements. Available only if 'Invalid' is
     returned in the 'reason' property.
    :vartype message: str
    """

    _validation = {
        'is_name_available': {'readonly': True},
        'reason': {'readonly': True},
        'message': {'readonly': True},
    }

    _attribute_map = {
        'is_name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(CheckNameAvailabilityOutput, self).__init__(**kwargs)
        self.is_name_available = None
        self.reason = None
        self.message = None
