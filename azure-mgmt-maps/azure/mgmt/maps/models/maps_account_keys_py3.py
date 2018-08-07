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


class MapsAccountKeys(Model):
    """The set of keys which can be used to access the Maps REST APIs. Two keys
    are provided for key rotation without interruption.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The full Azure resource identifier of the Maps Account.
    :vartype id: str
    :ivar primary_key: The primary key for accessing the Maps REST APIs.
    :vartype primary_key: str
    :ivar secondary_key: The secondary key for accessing the Maps REST APIs.
    :vartype secondary_key: str
    """

    _validation = {
        'id': {'readonly': True},
        'primary_key': {'readonly': True},
        'secondary_key': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'primary_key': {'key': 'primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'secondaryKey', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(MapsAccountKeys, self).__init__(**kwargs)
        self.id = None
        self.primary_key = None
        self.secondary_key = None
