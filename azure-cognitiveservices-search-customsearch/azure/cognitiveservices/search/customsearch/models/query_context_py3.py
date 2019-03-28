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


class QueryContext(Model):
    """Defines the query context that Bing used for the request.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param original_query: Required. The query string as specified in the
     request.
    :type original_query: str
    :ivar altered_query: The query string used by Bing to perform the query.
     Bing uses the altered query string if the original query string contained
     spelling mistakes. For example, if the query string is "saling downwind",
     the altered query string will be "sailing downwind". This field is
     included only if the original query string contains a spelling mistake.
    :vartype altered_query: str
    :ivar alteration_override_query: The query string to use to force Bing to
     use the original string. For example, if the query string is "saling
     downwind", the override query string will be "+saling downwind". Remember
     to encode the query string which results in "%2Bsaling+downwind". This
     field is included only if the original query string contains a spelling
     mistake.
    :vartype alteration_override_query: str
    :ivar adult_intent: A Boolean value that indicates whether the specified
     query has adult intent. The value is true if the query has adult intent;
     otherwise, false.
    :vartype adult_intent: bool
    """

    _validation = {
        'original_query': {'required': True},
        'altered_query': {'readonly': True},
        'alteration_override_query': {'readonly': True},
        'adult_intent': {'readonly': True},
    }

    _attribute_map = {
        'original_query': {'key': 'originalQuery', 'type': 'str'},
        'altered_query': {'key': 'alteredQuery', 'type': 'str'},
        'alteration_override_query': {'key': 'alterationOverrideQuery', 'type': 'str'},
        'adult_intent': {'key': 'adultIntent', 'type': 'bool'},
    }

    def __init__(self, *, original_query: str, **kwargs) -> None:
        super(QueryContext, self).__init__(**kwargs)
        self.original_query = original_query
        self.altered_query = None
        self.alteration_override_query = None
        self.adult_intent = None
