# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

import sys

if sys.version_info < (3,):
    def _str(value):
        if isinstance(value, unicode):  # pylint: disable=undefined-variable
            return value.encode('utf-8')

        return str(value)
else:
    _str = str


def _to_utc_datetime(value):
    return value.strftime('%Y-%m-%dT%H:%M:%SZ')


def get_empty_chunk(chunk_size):
    empty_chunk = b''
    for i in range(0, chunk_size):
        empty_chunk += b'\x00'
    return empty_chunk
