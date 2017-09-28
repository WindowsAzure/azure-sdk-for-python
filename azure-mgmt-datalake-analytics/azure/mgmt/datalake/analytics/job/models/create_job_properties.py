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


class CreateJobProperties(Model):
    """The common Data Lake Analytics job properties for job submission.

    :param runtime_version: the runtime version of the Data Lake Analytics
     engine to use for the specific type of job being run.
    :type runtime_version: str
    :param script: the script to run. Please note that the maximum script size
     is 3 MB.
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
        'type': {'USql': 'CreateUSqlJobProperties'}
    }

    def __init__(self, script, runtime_version=None):
        self.runtime_version = runtime_version
        self.script = script
        self.type = None
