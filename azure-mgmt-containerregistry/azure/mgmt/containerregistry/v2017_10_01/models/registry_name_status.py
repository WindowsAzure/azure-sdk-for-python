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


class RegistryNameStatus(Model):
    """The result of a request to check the availability of a container registry
    name.

    :param name_available: The value that indicates whether the name is
     available.
    :type name_available: bool
    :param reason: If any, the reason that the name is not available.
    :type reason: str
    :param message: If any, the error message that provides more detail for
     the reason that the name is not available.
    :type message: str
    """

    _attribute_map = {
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, name_available=None, reason=None, message=None):
        super(RegistryNameStatus, self).__init__()
        self.name_available = name_available
        self.reason = reason
        self.message = message
