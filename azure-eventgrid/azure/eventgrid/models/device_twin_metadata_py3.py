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


class DeviceTwinMetadata(Model):
    """Metadata information for the properties JSON document.

    :param last_updated: The ISO8601 timestamp of the last time the properties
     were updated.
    :type last_updated: str
    """

    _attribute_map = {
        'last_updated': {'key': 'lastUpdated', 'type': 'str'},
    }

    def __init__(self, *, last_updated: str=None, **kwargs) -> None:
        super(DeviceTwinMetadata, self).__init__(**kwargs)
        self.last_updated = last_updated
