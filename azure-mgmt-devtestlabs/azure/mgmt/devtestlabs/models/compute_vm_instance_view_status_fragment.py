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


class ComputeVmInstanceViewStatusFragment(Model):
    """Status information about a virtual machine.

    :param code: Gets the status Code.
    :type code: str
    :param display_status: Gets the short localizable label for the status.
    :type display_status: str
    :param message: Gets the message associated with the status.
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'display_status': {'key': 'displayStatus', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, code=None, display_status=None, message=None):
        super(ComputeVmInstanceViewStatusFragment, self).__init__()
        self.code = code
        self.display_status = display_status
        self.message = message
