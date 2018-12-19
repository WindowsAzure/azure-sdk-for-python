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


class MapsAccountProperties(Model):
    """Additional Map account properties.

    :param x_ms_client_id: A unique identifier for the maps account
    :type x_ms_client_id: str
    """

    _attribute_map = {
        'x_ms_client_id': {'key': 'x-ms-client-id', 'type': 'str'},
    }

    def __init__(self, *, x_ms_client_id: str=None, **kwargs) -> None:
        super(MapsAccountProperties, self).__init__(**kwargs)
        self.x_ms_client_id = x_ms_client_id
