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


class CheckNameAvailabilityResponse(Model):
    """A response indicating whether the specified name for a resource is
    available.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar available: True if the name is available, otherwise false.
    :vartype available: bool
    :ivar message: A message explaining why the name is unavailable. Will be
     null if the name is available.
    :vartype message: str
    :ivar name: The name whose availability was checked.
    :vartype name: str
    :ivar reason: The reason code explaining why the name is unavailable. Will
     be null if the name is available. Possible values include: 'Invalid',
     'AlreadyExists'
    :vartype reason: str or ~azure.mgmt.sql.models.CheckNameAvailabilityReason
    """

    _validation = {
        'available': {'readonly': True},
        'message': {'readonly': True},
        'name': {'readonly': True},
        'reason': {'readonly': True},
    }

    _attribute_map = {
        'available': {'key': 'available', 'type': 'bool'},
        'message': {'key': 'message', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'reason': {'key': 'reason', 'type': 'CheckNameAvailabilityReason'},
    }

    def __init__(self, **kwargs) -> None:
        super(CheckNameAvailabilityResponse, self).__init__(**kwargs)
        self.available = None
        self.message = None
        self.name = None
        self.reason = None
