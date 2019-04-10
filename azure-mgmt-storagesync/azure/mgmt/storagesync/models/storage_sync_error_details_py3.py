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


class StorageSyncErrorDetails(Model):
    """Error Details object.

    :param code: Error code of the given entry.
    :type code: str
    :param message: Error message of the given entry.
    :type message: str
    :param target: Target of the given entry.
    :type target: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
    }

    def __init__(self, *, code: str=None, message: str=None, target: str=None, **kwargs) -> None:
        super(StorageSyncErrorDetails, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.target = target
