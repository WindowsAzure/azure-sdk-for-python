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


class EntityRecord(Model):
    """EntityRecord.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param name: Entity formal name.
    :type name: str
    :ivar matches: List of instances this entity appears in the text.
    :vartype matches:
     list[~azure.cognitiveservices.language.textanalytics.models.MatchRecord]
    :param wikipedia_language: Wikipedia language for which the WikipediaId
     and WikipediaUrl refers to.
    :type wikipedia_language: str
    :param wikipedia_id: Wikipedia unique identifier of the recognized entity.
    :type wikipedia_id: str
    :ivar wikipedia_url: URL for the entity's English Wikipedia page.
    :vartype wikipedia_url: str
    :param bing_id: Bing unique identifier of the recognized entity. Use in
     conjunction with the Bing Entity Search API to fetch additional relevant
     information.
    :type bing_id: str
    """

    _validation = {
        'matches': {'readonly': True},
        'wikipedia_url': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'matches': {'key': 'matches', 'type': '[MatchRecord]'},
        'wikipedia_language': {'key': 'wikipediaLanguage', 'type': 'str'},
        'wikipedia_id': {'key': 'wikipediaId', 'type': 'str'},
        'wikipedia_url': {'key': 'wikipediaUrl', 'type': 'str'},
        'bing_id': {'key': 'bingId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(EntityRecord, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.matches = None
        self.wikipedia_language = kwargs.get('wikipedia_language', None)
        self.wikipedia_id = kwargs.get('wikipedia_id', None)
        self.wikipedia_url = None
        self.bing_id = kwargs.get('bing_id', None)
