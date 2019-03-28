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

from .mongo_db_command_input_py3 import MongoDbCommandInput


class MongoDbFinishCommandInput(MongoDbCommandInput):
    """Describes the input to the 'finish' MongoDB migration command.

    All required parameters must be populated in order to send to Azure.

    :param object_name: The qualified name of a database or collection to act
     upon, or null to act upon the entire migration
    :type object_name: str
    :param immediate: Required. If true, replication for the affected objects
     will be stopped immediately. If false, the migrator will finish replaying
     queued events before finishing the replication.
    :type immediate: bool
    """

    _validation = {
        'immediate': {'required': True},
    }

    _attribute_map = {
        'object_name': {'key': 'objectName', 'type': 'str'},
        'immediate': {'key': 'immediate', 'type': 'bool'},
    }

    def __init__(self, *, immediate: bool, object_name: str=None, **kwargs) -> None:
        super(MongoDbFinishCommandInput, self).__init__(object_name=object_name, **kwargs)
        self.immediate = immediate
