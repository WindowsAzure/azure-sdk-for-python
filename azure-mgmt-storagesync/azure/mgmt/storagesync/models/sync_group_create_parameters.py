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


class SyncGroupCreateParameters(Model):
    """The parameters used when creating a sync group.

    :param properties: The parameters used to create the sync group
    :type properties: object
    """

    _attribute_map = {
        'properties': {'key': 'properties', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(SyncGroupCreateParameters, self).__init__(**kwargs)
        self.properties = kwargs.get('properties', None)
