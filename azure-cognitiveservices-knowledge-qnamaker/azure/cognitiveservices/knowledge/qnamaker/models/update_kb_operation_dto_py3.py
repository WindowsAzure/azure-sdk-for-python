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


class UpdateKbOperationDTO(Model):
    """Contains list of QnAs to be updated.

    :param add: An instance of CreateKbInputDTO for add operation
    :type add:
     ~azure.cognitiveservices.knowledge.qnamaker.models.UpdateKbOperationDTOAdd
    :param delete: An instance of DeleteKbContentsDTO for delete Operation
    :type delete:
     ~azure.cognitiveservices.knowledge.qnamaker.models.UpdateKbOperationDTODelete
    :param update: An instance of UpdateKbContentsDTO for Update Operation
    :type update:
     ~azure.cognitiveservices.knowledge.qnamaker.models.UpdateKbOperationDTOUpdate
    """

    _attribute_map = {
        'add': {'key': 'add', 'type': 'UpdateKbOperationDTOAdd'},
        'delete': {'key': 'delete', 'type': 'UpdateKbOperationDTODelete'},
        'update': {'key': 'update', 'type': 'UpdateKbOperationDTOUpdate'},
    }

    def __init__(self, *, add=None, delete=None, update=None, **kwargs) -> None:
        super(UpdateKbOperationDTO, self).__init__(**kwargs)
        self.add = add
        self.delete = delete
        self.update = update
