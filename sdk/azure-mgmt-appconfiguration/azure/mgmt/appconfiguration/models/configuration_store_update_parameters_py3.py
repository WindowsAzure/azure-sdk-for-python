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


class ConfigurationStoreUpdateParameters(Model):
    """The parameters for updating a configuration store.

    :param properties: The properties for updating a configuration store.
    :type properties: object
    :param tags: The ARM resource tags.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'properties': {'key': 'properties', 'type': 'object'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, properties=None, tags=None, **kwargs) -> None:
        super(ConfigurationStoreUpdateParameters, self).__init__(**kwargs)
        self.properties = properties
        self.tags = tags
