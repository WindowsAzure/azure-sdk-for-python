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

from .search_results_answer import SearchResultsAnswer


class WebWebAnswer(SearchResultsAnswer):
    """Defines a list of relevant webpage links.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param _type: Constant filled by server.
    :type _type: str
    :ivar id: A String identifier.
    :vartype id: str
    :ivar web_search_url: The URL To Bing's search result for this item.
    :vartype web_search_url: str
    :ivar follow_up_queries:
    :vartype follow_up_queries:
     list[~azure.cognitiveservices.search.customsearch.models.Query]
    :ivar query_context:
    :vartype query_context:
     ~azure.cognitiveservices.search.customsearch.models.QueryContext
    :ivar total_estimated_matches: The estimated number of webpages that are
     relevant to the query. Use this number along with the count and offset
     query parameters to page the results.
    :vartype total_estimated_matches: long
    :ivar is_family_friendly:
    :vartype is_family_friendly: bool
    :param value: A list of webpages that are relevant to the query.
    :type value:
     list[~azure.cognitiveservices.search.customsearch.models.WebPage]
    :ivar some_results_removed: A Boolean value that indicates whether the
     response excluded some results from the answer. If Bing excluded some
     results, the value is true.
    :vartype some_results_removed: bool
    """

    _validation = {
        '_type': {'required': True},
        'id': {'readonly': True},
        'web_search_url': {'readonly': True},
        'follow_up_queries': {'readonly': True},
        'query_context': {'readonly': True},
        'total_estimated_matches': {'readonly': True},
        'is_family_friendly': {'readonly': True},
        'value': {'required': True},
        'some_results_removed': {'readonly': True},
    }

    _attribute_map = {
        '_type': {'key': '_type', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'web_search_url': {'key': 'webSearchUrl', 'type': 'str'},
        'follow_up_queries': {'key': 'followUpQueries', 'type': '[Query]'},
        'query_context': {'key': 'queryContext', 'type': 'QueryContext'},
        'total_estimated_matches': {'key': 'totalEstimatedMatches', 'type': 'long'},
        'is_family_friendly': {'key': 'isFamilyFriendly', 'type': 'bool'},
        'value': {'key': 'value', 'type': '[WebPage]'},
        'some_results_removed': {'key': 'someResultsRemoved', 'type': 'bool'},
    }

    def __init__(self, value):
        super(WebWebAnswer, self).__init__()
        self.value = value
        self.some_results_removed = None
        self._type = 'Web/WebAnswer'
