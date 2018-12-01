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

from .search_results_answer_py3 import SearchResultsAnswer


class Places(SearchResultsAnswer):
    """Defines a local entity answer.

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
    :ivar query_context:
    :vartype query_context:
     ~azure.cognitiveservices.search.entitysearch.models.QueryContext
    :param value: Required. A list of local entities, such as restaurants or
     hotels.
    :type value:
     list[~azure.cognitiveservices.search.entitysearch.models.Thing]
    """

    _validation = {
        '_type': {'required': True},
        'id': {'readonly': True},
        'contractual_rules': {'readonly': True},
        'web_search_url': {'readonly': True},
        'query_context': {'readonly': True},
        'value': {'required': True},
    }

    _attribute_map = {
        '_type': {'key': '_type', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'contractual_rules': {'key': 'contractualRules', 'type': '[ContractualRulesContractualRule]'},
        'web_search_url': {'key': 'webSearchUrl', 'type': 'str'},
        'query_context': {'key': 'queryContext', 'type': 'QueryContext'},
        'value': {'key': 'value', 'type': '[Thing]'},
    }

    def __init__(self, *, value, **kwargs) -> None:
        super(Places, self).__init__(**kwargs)
        self.value = value
        self._type = 'Places'
