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

from .meta_data_contract import MetaDataContract


class LargeFaceList(MetaDataContract):
    """Large face list object.

    All required parameters must be populated in order to send to Azure.

    :param name: User defined name, maximum length is 128.
    :type name: str
    :param user_data: User specified data. Length should not exceed 16KB.
    :type user_data: str
    :param recognition_model: Possible values include: 'recognition_01',
     'recognition_02'. Default value: "recognition_01" .
    :type recognition_model: str or
     ~azure.cognitiveservices.vision.face.models.RecognitionModel
    :param large_face_list_id: Required. LargeFaceListId of the target large
     face list.
    :type large_face_list_id: str
    """

    _validation = {
        'name': {'max_length': 128},
        'user_data': {'max_length': 16384},
        'large_face_list_id': {'required': True, 'max_length': 64, 'pattern': r'^[a-z0-9-_]+$'},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'user_data': {'key': 'userData', 'type': 'str'},
        'recognition_model': {'key': 'recognitionModel', 'type': 'str'},
        'large_face_list_id': {'key': 'largeFaceListId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(LargeFaceList, self).__init__(**kwargs)
        self.large_face_list_id = kwargs.get('large_face_list_id', None)
