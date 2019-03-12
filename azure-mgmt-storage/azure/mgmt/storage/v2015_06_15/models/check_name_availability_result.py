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

    :param name_available: Boolean value that indicates whether the name is
     available for you to use. If true, the name is available. If false, the
     name has already been taken or is invalid and cannot be used.
    :type name_available: bool
    :param reason: The reason that a storage account name could not be used.
     The Reason element is only returned if NameAvailable is false. Possible
     values include: 'AccountNameInvalid', 'AlreadyExists'
    :type reason: str or ~azure.mgmt.storage.v2015_06_15.models.Reason
    :param message: The error message explaining the Reason value in more
     detail.
    :type message: str
    """

    _attribute_map = {
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'Reason'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(CheckNameAvailabilityResult, self).__init__(**kwargs)
        self.name_available = kwargs.get('name_available', None)
        self.reason = kwargs.get('reason', None)
        self.message = kwargs.get('message', None)
