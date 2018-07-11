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


class WorkspaceCollectionAccessKeys(Model):
    """WorkspaceCollectionAccessKeys.

    :param key1: Access key 1
    :type key1: str
    :param key2: Access key 2
    :type key2: str
    """

    _attribute_map = {
        'key1': {'key': 'key1', 'type': 'str'},
        'key2': {'key': 'key2', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(WorkspaceCollectionAccessKeys, self).__init__(**kwargs)
        self.key1 = kwargs.get('key1', None)
        self.key2 = kwargs.get('key2', None)
