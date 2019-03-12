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

from .thing import Thing


class Intangible(Thing):
    """Intangible.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: StructuredValue

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param _type: Required. Constant filled by server.
    :type _type: str
    :ivar id: A String identifier.
    :vartype id: str
    :ivar contractual_rules: A list of rules that you must adhere to if you
     display the item.
    :vartype contractual_rules:
     list[~azure.cognitiveservices.search.entitysearch.models.ContractualRulesContractualRule]
    :ivar web_search_url: The URL To Bing's search result for this item.
    :vartype web_search_url: str
    :ivar name: The name of the thing represented by this object.
    :vartype name: str
    :ivar url: The URL to get more information about the thing represented by
     this object.
    :vartype url: str
    :ivar image:
    :vartype image:
     ~azure.cognitiveservices.search.entitysearch.models.ImageObject
    :ivar description: A short description of the item.
    :vartype description: str
    :ivar entity_presentation_info: Additional information about the entity
     such as hints that you can use to determine the entity's type. To
     determine the entity's type, use the entityScenario and entityTypeHint
     fields.
    :vartype entity_presentation_info:
     ~azure.cognitiveservices.search.entitysearch.models.EntitiesEntityPresentationInfo
    :ivar bing_id: An ID that uniquely identifies this item.
    :vartype bing_id: str
    """

    _validation = {
        '_type': {'required': True},
        'id': {'readonly': True},
        'contractual_rules': {'readonly': True},
        'web_search_url': {'readonly': True},
        'name': {'readonly': True},
        'url': {'readonly': True},
        'image': {'readonly': True},
        'description': {'readonly': True},
        'entity_presentation_info': {'readonly': True},
        'bing_id': {'readonly': True},
    }

    _attribute_map = {
        '_type': {'key': '_type', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'contractual_rules': {'key': 'contractualRules', 'type': '[ContractualRulesContractualRule]'},
        'web_search_url': {'key': 'webSearchUrl', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'image': {'key': 'image', 'type': 'ImageObject'},
        'description': {'key': 'description', 'type': 'str'},
        'entity_presentation_info': {'key': 'entityPresentationInfo', 'type': 'EntitiesEntityPresentationInfo'},
        'bing_id': {'key': 'bingId', 'type': 'str'},
    }

    _subtype_map = {
        '_type': {'StructuredValue': 'StructuredValue'}
    }

    def __init__(self, **kwargs):
        super(Intangible, self).__init__(**kwargs)
        self._type = 'Intangible'
