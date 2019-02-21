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


class ResourceNameAvailability(Model):
    """Information regarding availability of a resource name.

    :param name_available: <code>true</code> indicates name is valid and
     available. <code>false</code> indicates the name is invalid, unavailable,
     or both.
    :type name_available: bool
    :param reason: <code>Invalid</code> indicates the name provided does not
     match Azure App Service naming requirements. <code>AlreadyExists</code>
     indicates that the name is already in use and is therefore unavailable.
     Possible values include: 'Invalid', 'AlreadyExists'
    :type reason: str or ~azure.mgmt.web.models.InAvailabilityReasonType
    :param message: If reason == invalid, provide the user with the reason why
     the given name is invalid, and provide the resource naming requirements so
     that the user can select a valid name. If reason == AlreadyExists, explain
     that resource name is already in use, and direct them to select a
     different name.
    :type message: str
    """

    _attribute_map = {
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ResourceNameAvailability, self).__init__(**kwargs)
        self.name_available = kwargs.get('name_available', None)
        self.reason = kwargs.get('reason', None)
        self.message = kwargs.get('message', None)
