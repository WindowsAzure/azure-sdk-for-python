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
    """The CheckNameAvailability operation response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name_available: Gets a boolean value that indicates whether the name
     is available for you to use. If true, the name is available. If false, the
     name has already been taken or is invalid and cannot be used.
    :vartype name_available: bool
    :ivar reason: Gets the reason that a storage account name could not be
     used. The Reason element is only returned if NameAvailable is false.
     Possible values include: 'AccountNameInvalid', 'AlreadyExists'
    :vartype reason: str or
     ~azure.mgmt.storage.v2018_03_01_preview.models.Reason
    :ivar message: Gets an error message explaining the Reason value in more
     detail.
    :vartype message: str
    """

    _validation = {
        'name_available': {'readonly': True},
        'reason': {'readonly': True},
        'message': {'readonly': True},
    }

    _attribute_map = {
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'Reason'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(CheckNameAvailabilityResult, self).__init__(**kwargs)
        self.name_available = None
        self.reason = None
        self.message = None
