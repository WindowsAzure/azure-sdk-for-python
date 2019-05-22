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

from .meta_data_contract_py3 import MetaDataContract


class LargePersonGroup(MetaDataContract):
    """Large person group object.

    All required parameters must be populated in order to send to Azure.

    :param name: User defined name, maximum length is 128.
    :type name: str
    :param user_data: User specified data. Length should not exceed 16KB.
    :type user_data: str
    :param recognition_model: Possible values include: 'recognition_01',
     'recognition_02'. Default value: "recognition_01" .
    :type recognition_model: str or
     ~azure.cognitiveservices.vision.face.models.RecognitionModel
    :param large_person_group_id: Required. LargePersonGroupId of the target
     large person groups
    :type large_person_group_id: str
    """

    _validation = {
        'name': {'max_length': 128},
        'user_data': {'max_length': 16384},
        'large_person_group_id': {'required': True, 'max_length': 64, 'pattern': r'^[a-z0-9-_]+$'},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'user_data': {'key': 'userData', 'type': 'str'},
        'recognition_model': {'key': 'recognitionModel', 'type': 'str'},
        'large_person_group_id': {'key': 'largePersonGroupId', 'type': 'str'},
    }

    def __init__(self, *, large_person_group_id: str, name: str=None, user_data: str=None, recognition_model="recognition_01", **kwargs) -> None:
        super(LargePersonGroup, self).__init__(name=name, user_data=user_data, recognition_model=recognition_model, **kwargs)
        self.large_person_group_id = large_person_group_id
