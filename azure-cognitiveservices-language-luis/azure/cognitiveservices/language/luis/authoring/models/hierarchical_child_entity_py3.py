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

from .child_entity_py3 import ChildEntity


class HierarchicalChildEntity(ChildEntity):
    """A Hierarchical Child Entity.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. The ID (GUID) belonging to a child entity.
    :type id: str
    :param name: The name of a child entity.
    :type name: str
    :param type_id: The type ID of the Entity Model.
    :type type_id: int
    :param readable_type: Possible values include: 'Entity Extractor',
     'Hierarchical Entity Extractor', 'Hierarchical Child Entity Extractor',
     'Composite Entity Extractor', 'List Entity Extractor', 'Prebuilt Entity
     Extractor', 'Intent Classifier', 'Pattern.Any Entity Extractor', 'Regular
     Expression Entity Extractor', 'Closed List Entity Extractor', 'Regex
     Entity Extractor'
    :type readable_type: str or
     ~azure.cognitiveservices.language.luis.authoring.models.enum
    """

    _validation = {
        'id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type_id': {'key': 'typeId', 'type': 'int'},
        'readable_type': {'key': 'readableType', 'type': 'str'},
    }

    def __init__(self, *, id: str, name: str=None, type_id: int=None, readable_type=None, **kwargs) -> None:
        super(HierarchicalChildEntity, self).__init__(id=id, name=name, **kwargs)
        self.type_id = type_id
        self.readable_type = readable_type
