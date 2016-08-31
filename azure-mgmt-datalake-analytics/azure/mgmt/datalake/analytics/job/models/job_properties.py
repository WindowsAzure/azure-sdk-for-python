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


class JobProperties(Model):
    """The common Data Lake Analytics job properties.

    :param runtime_version: Gets or sets the runtime version of the U-SQL
     engine to use
    :type runtime_version: str
    :param script: Gets or sets the U-SQL script to run
    :type script: str
    :param type: Polymorphic Discriminator
    :type type: str
    """ 

    _validation = {
        'script': {'required': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'runtime_version': {'key': 'runtimeVersion', 'type': 'str'},
        'script': {'key': 'script', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    _subtype_map = {
        'type': {'USql': 'USqlJobProperties', 'Hive': 'HiveJobProperties'}
    }

    def __init__(self, script, runtime_version=None):
        self.runtime_version = runtime_version
        self.script = script
        self.type = None
