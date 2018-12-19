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


class NameAndUserDataContract(Model):
    """A combination of user defined name and user specified data for the person,
    largePersonGroup/personGroup, and largeFaceList/faceList.

    :param name: User defined name, maximum length is 128.
    :type name: str
    :param user_data: User specified data. Length should not exceed 16KB.
    :type user_data: str
    """

    _validation = {
        'name': {'max_length': 128},
        'user_data': {'max_length': 16384},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'user_data': {'key': 'userData', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(NameAndUserDataContract, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.user_data = kwargs.get('user_data', None)
