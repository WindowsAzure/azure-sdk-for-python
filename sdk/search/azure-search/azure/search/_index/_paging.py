# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from typing import TYPE_CHECKING

import base64
import json

from azure.core.paging import ItemPaged, PageIterator, ReturnType
from ._generated.models import SearchRequest

if TYPE_CHECKING:
    # pylint:disable=unused-import,ungrouped-imports
    from typing import Any, Union


def convert_search_result(result):
    ret = result.additional_properties
    ret["@search.score"] = result.score
    ret["@search.highlights"] = result.highlights
    return ret


def pack_continuation_token(response):
    if response.next_page_parameters is not None:
        return base64.b64encode(
            json.dumps(
                [response.next_link, response.next_page_parameters.serialize()]
            ).encode("utf-8")
        )
    return None


def unpack_continuation_token(token):
    next_link, next_page_parameters = json.loads(base64.b64decode(token))
    next_page_request = SearchRequest.deserialize(next_page_parameters)
    return next_link, next_page_request


class SearchItemPaged(ItemPaged[ReturnType]):
    pass


class SearchPageIterator(PageIterator):
    def __init__(self, client, initial_query, kwargs, continuation_token=None):
        super(SearchPageIterator, self).__init__(
            get_next=self._get_next_cb,
            extract_data=self._extract_data_cb,
            continuation_token=continuation_token,
        )
        self._client = client
        self._initial_query = initial_query
        self._kwargs = kwargs

    def _get_next_cb(self, continuation_token):
        if continuation_token is None:
            return self._client.documents.search_post(
                search_request=self._initial_query.request, **self._kwargs
            )

        _next_link, next_page_request = unpack_continuation_token(continuation_token)

        return self._client.documents.search_post(search_request=next_page_request)

    def _extract_data_cb(self, response):  # pylint:disable=no-self-use
        continuation_token = pack_continuation_token(response)

        results = [convert_search_result(r) for r in response.results]

        return continuation_token, results
