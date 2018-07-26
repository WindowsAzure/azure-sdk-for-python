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


class NameAvailabilityResponse(Model):
    """Indicates whether a proposed resource name is available.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name_available: If true, the name is valid and available. If false,
     'reason' describes why not.
    :vartype name_available: bool
    :ivar reason: The reason why the name is not available, if nameAvailable
     is false. Possible values include: 'AlreadyExists', 'Invalid'
    :vartype reason: str or
     ~azure.mgmt.datamigration.models.NameCheckFailureReason
    :ivar message: The localized reason why the name is not available, if
     nameAvailable is false
    :vartype message: str
    """

    _validation = {
        'name_available': {'readonly': True},
        'reason': {'readonly': True},
        'message': {'readonly': True},
    }

    _attribute_map = {
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(NameAvailabilityResponse, self).__init__(**kwargs)
        self.name_available = None
        self.reason = None
        self.message = None
