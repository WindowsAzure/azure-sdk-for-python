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


class DscNodeConfigurationAssociationProperty(Model):
    """The dsc nodeconfiguration property associated with the entity.

    :param name: Gets or sets the name of the dsc nodeconfiguration.
    :type name: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, **kwargs) -> None:
        super(DscNodeConfigurationAssociationProperty, self).__init__(**kwargs)
        self.name = name
