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


class Endpoints(Model):
    """The URIs that are used to perform a retrieval of a public blob, queue, or
    table object.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar blob: Gets the blob endpoint.
    :vartype blob: str
    :ivar queue: Gets the queue endpoint.
    :vartype queue: str
    :ivar table: Gets the table endpoint.
    :vartype table: str
    :ivar file: Gets the file endpoint.
    :vartype file: str
    """

    _validation = {
        'blob': {'readonly': True},
        'queue': {'readonly': True},
        'table': {'readonly': True},
        'file': {'readonly': True},
    }

    _attribute_map = {
        'blob': {'key': 'blob', 'type': 'str'},
        'queue': {'key': 'queue', 'type': 'str'},
        'table': {'key': 'table', 'type': 'str'},
        'file': {'key': 'file', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Endpoints, self).__init__(**kwargs)
        self.blob = None
        self.queue = None
        self.table = None
        self.file = None
