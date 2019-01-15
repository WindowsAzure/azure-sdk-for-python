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


class UpdateFaceRequest(Model):
    """Request to update face data.

    :param user_data: User-provided data attached to the face. The size limit
     is 1KB.
    :type user_data: str
    """

    _validation = {
        'user_data': {'max_length': 1024},
    }

    _attribute_map = {
        'user_data': {'key': 'userData', 'type': 'str'},
    }

    def __init__(self, *, user_data: str=None, **kwargs) -> None:
        super(UpdateFaceRequest, self).__init__(**kwargs)
        self.user_data = user_data
