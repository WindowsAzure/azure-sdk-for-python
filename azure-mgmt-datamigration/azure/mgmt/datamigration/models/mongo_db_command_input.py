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


class MongoDbCommandInput(Model):
    """Describes the input to the 'cancel' and 'restart' MongoDB migration
    commands.

    :param object_name: The qualified name of a database or collection to act
     upon, or null to act upon the entire migration
    :type object_name: str
    """

    _attribute_map = {
        'object_name': {'key': 'objectName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(MongoDbCommandInput, self).__init__(**kwargs)
        self.object_name = kwargs.get('object_name', None)
