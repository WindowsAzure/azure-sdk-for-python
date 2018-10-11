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

from .copy_source_py3 import CopySource


class OracleSource(CopySource):
    """A copy activity Oracle source.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param source_retry_count: Source retry count. Type: integer (or
     Expression with resultType integer).
    :type source_retry_count: object
    :param source_retry_wait: Source retry wait. Type: string (or Expression
     with resultType string), pattern:
     ((\\d+)\\.)?(\\d\\d):(60|([0-5][0-9])):(60|([0-5][0-9])).
    :type source_retry_wait: object
    :param type: Required. Constant filled by server.
    :type type: str
    :param oracle_reader_query: Oracle reader query. Type: string (or
     Expression with resultType string).
    :type oracle_reader_query: object
    :param query_timeout: Query timeout. Type: string (or Expression with
     resultType string), pattern:
     ((\\d+)\\.)?(\\d\\d):(60|([0-5][0-9])):(60|([0-5][0-9])).
    :type query_timeout: object
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'source_retry_count': {'key': 'sourceRetryCount', 'type': 'object'},
        'source_retry_wait': {'key': 'sourceRetryWait', 'type': 'object'},
        'type': {'key': 'type', 'type': 'str'},
        'oracle_reader_query': {'key': 'oracleReaderQuery', 'type': 'object'},
        'query_timeout': {'key': 'queryTimeout', 'type': 'object'},
    }

    def __init__(self, *, additional_properties=None, source_retry_count=None, source_retry_wait=None, oracle_reader_query=None, query_timeout=None, **kwargs) -> None:
        super(OracleSource, self).__init__(additional_properties=additional_properties, source_retry_count=source_retry_count, source_retry_wait=source_retry_wait, **kwargs)
        self.oracle_reader_query = oracle_reader_query
        self.query_timeout = query_timeout
        self.type = 'OracleSource'
