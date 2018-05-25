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


class WorkspaceCollectionAccessKey(Model):
    """WorkspaceCollectionAccessKey.

    :param key_name: Key name. Possible values include: 'key1', 'key2'
    :type key_name: str or ~azure.mgmt.powerbiembedded.models.AccessKeyName
    """

    _attribute_map = {
        'key_name': {'key': 'keyName', 'type': 'AccessKeyName'},
    }

    def __init__(self, **kwargs):
        super(WorkspaceCollectionAccessKey, self).__init__(**kwargs)
        self.key_name = kwargs.get('key_name', None)
