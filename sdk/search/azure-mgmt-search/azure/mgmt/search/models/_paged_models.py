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

from msrest.paging import Paged


class OperationPaged(Paged):
    """
    A paging container for iterating over a list of :class:`Operation <azure.mgmt.search.models.Operation>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Operation]'}
    }

    def __init__(self, *args, **kwargs):

        super(OperationPaged, self).__init__(*args, **kwargs)
class QueryKeyPaged(Paged):
    """
    A paging container for iterating over a list of :class:`QueryKey <azure.mgmt.search.models.QueryKey>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[QueryKey]'}
    }

    def __init__(self, *args, **kwargs):

        super(QueryKeyPaged, self).__init__(*args, **kwargs)
class SearchServicePaged(Paged):
    """
    A paging container for iterating over a list of :class:`SearchService <azure.mgmt.search.models.SearchService>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[SearchService]'}
    }

    def __init__(self, *args, **kwargs):

        super(SearchServicePaged, self).__init__(*args, **kwargs)
class PrivateLinkResourcePaged(Paged):
    """
    A paging container for iterating over a list of :class:`PrivateLinkResource <azure.mgmt.search.models.PrivateLinkResource>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[PrivateLinkResource]'}
    }

    def __init__(self, *args, **kwargs):

        super(PrivateLinkResourcePaged, self).__init__(*args, **kwargs)
class PrivateEndpointConnectionPaged(Paged):
    """
    A paging container for iterating over a list of :class:`PrivateEndpointConnection <azure.mgmt.search.models.PrivateEndpointConnection>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[PrivateEndpointConnection]'}
    }

    def __init__(self, *args, **kwargs):

        super(PrivateEndpointConnectionPaged, self).__init__(*args, **kwargs)
class SharedPrivateLinkResourcePaged(Paged):
    """
    A paging container for iterating over a list of :class:`SharedPrivateLinkResource <azure.mgmt.search.models.SharedPrivateLinkResource>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[SharedPrivateLinkResource]'}
    }

    def __init__(self, *args, **kwargs):

        super(SharedPrivateLinkResourcePaged, self).__init__(*args, **kwargs)
