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

from .response import Response


class Thing(Response):
    """Defines a thing.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: CreativeWork

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param _type: Required. Constant filled by server.
    :type _type: str
    :ivar id: A String identifier.
    :vartype id: str
    :ivar potential_action:
    :vartype potential_action:
     list[~azure.cognitiveservices.search.autosuggest.models.Action]
    :ivar immediate_action:
    :vartype immediate_action:
     list[~azure.cognitiveservices.search.autosuggest.models.Action]
    :ivar adaptive_card:
    :vartype adaptive_card: str
    :ivar name: The name of the thing represented by this object.
    :vartype name: str
    :ivar description: A short description of the item.
    :vartype description: str
    :ivar wikipedia_id:
    :vartype wikipedia_id: str
    :ivar freebase_id:
    :vartype freebase_id: str
    :ivar alternate_name: An alias for the item
    :vartype alternate_name: str
    :ivar bing_id: An ID that uniquely identifies this item.
    :vartype bing_id: str
    :ivar satori_id:
    :vartype satori_id: str
    :ivar yp_id:
    :vartype yp_id: str
    """

    _validation = {
        '_type': {'required': True},
        'id': {'readonly': True},
        'potential_action': {'readonly': True},
        'immediate_action': {'readonly': True},
        'adaptive_card': {'readonly': True},
        'name': {'readonly': True},
        'description': {'readonly': True},
        'wikipedia_id': {'readonly': True},
        'freebase_id': {'readonly': True},
        'alternate_name': {'readonly': True},
        'bing_id': {'readonly': True},
        'satori_id': {'readonly': True},
        'yp_id': {'readonly': True},
    }

    _attribute_map = {
        '_type': {'key': '_type', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'potential_action': {'key': 'potentialAction', 'type': '[Action]'},
        'immediate_action': {'key': 'immediateAction', 'type': '[Action]'},
        'adaptive_card': {'key': 'adaptiveCard', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'wikipedia_id': {'key': 'wikipediaId', 'type': 'str'},
        'freebase_id': {'key': 'freebaseId', 'type': 'str'},
        'alternate_name': {'key': 'alternateName', 'type': 'str'},
        'bing_id': {'key': 'bingId', 'type': 'str'},
        'satori_id': {'key': 'satoriId', 'type': 'str'},
        'yp_id': {'key': 'ypId', 'type': 'str'},
    }

    _subtype_map = {
        '_type': {'CreativeWork': 'CreativeWork'}
    }

    def __init__(self, **kwargs):
        super(Thing, self).__init__(**kwargs)
        self.name = None
        self.description = None
        self.wikipedia_id = None
        self.freebase_id = None
        self.alternate_name = None
        self.bing_id = None
        self.satori_id = None
        self.yp_id = None
        self._type = 'Thing'
