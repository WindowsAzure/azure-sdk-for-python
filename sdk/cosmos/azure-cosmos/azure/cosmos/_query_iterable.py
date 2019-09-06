﻿# The MIT License (MIT)
# Copyright (c) 2014 Microsoft Corporation

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Iterable query results in the Azure Cosmos database service.
"""
from azure.core.paging import PageIterator  # type: ignore
from azure.cosmos._execution_context import execution_dispatcher
from azure.cosmos._execution_context import base_execution_context

# pylint: disable=protected-access


class QueryIterable(PageIterator):
    """Represents an iterable object of the query results.
    QueryIterable is a wrapper for query execution context.
    """

    def __init__(
        self,
        client,
        query,
        options,
        fetch_function=None,
        collection_link=None,
        database_link=None,
        partition_key=None,
        continuation_token=None,
    ):
        """
        Instantiates a QueryIterable for non-client side partitioning queries.
        _ProxyQueryExecutionContext will be used as the internal query execution context

        :param CosmosClient client:
            Instance of document client.
        :param (str or dict) query:
        :param dict options:
            The request options for the request.
        :param method fetch_function:
        :param str collection_link:
            If this is a Document query/feed collection_link is required.

        Example of `fetch_function`:

        >>> def result_fn(result):
        >>>     return result['Databases']

        """
        self._client = client
        self.retry_options = client.connection_policy.RetryOptions
        self._query = query
        self._options = options
        if continuation_token:
            self._options['continuation'] = continuation_token
        self._fetch_function = fetch_function
        self._collection_link = collection_link
        self._database_link = database_link
        self._partition_key = partition_key
        self._ex_context = self._create_execution_context()
        super(QueryIterable, self).__init__(self._fetch_next, self._unpack, continuation_token=continuation_token)

    def _create_execution_context(self):
        """instantiates the internal query execution context based.
        """
        if self._database_link:
            # client side partitioning query
            return base_execution_context._MultiCollectionQueryExecutionContext(
                self._client, self._options, self._database_link, self._query, self._partition_key
            )
        return execution_dispatcher._ProxyQueryExecutionContext(
            self._client, self._collection_link, self._query, self._options, self._fetch_function
        )

    def _unpack(self, block):
        if block:
            self._did_a_call_already = False
        return self._ex_context._continuation, block

    def _fetch_next(self, continuation):
        """Returns a block of results with respecting retry policy.

        This method only exists for backward compatibility reasons. (Because QueryIterable
        has exposed fetch_next_block api).

        :return:
            List of results.
        :rtype:
            list
        """
        self._ex_context._continuation = continuation
        block = self._ex_context.fetch_next_block()
        if not block:
            raise StopIteration
        return block
