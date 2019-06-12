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


class OverrideTaskStepProperties(Model):
    """OverrideTaskStepProperties.

    :param context_path: The source context against which run has to be
     queued.
    :type context_path: str
    :param file: The file against which run has to be queued.
    :type file: str
    :param arguments: Gets or sets the collection of override arguments to be
     used when
     executing a build step.
    :type arguments:
     list[~azure.mgmt.containerregistry.v2019_06_01_preview.models.Argument]
    :param target: The name of the target build stage for the docker build.
    :type target: str
    :param values: The collection of overridable values that can be passed
     when running a Task.
    :type values:
     list[~azure.mgmt.containerregistry.v2019_06_01_preview.models.SetValue]
    :param update_trigger_token: Base64 encoded update trigger token that will
     be attached with the base image trigger webhook.
    :type update_trigger_token: str
    """

    _attribute_map = {
        'context_path': {'key': 'contextPath', 'type': 'str'},
        'file': {'key': 'file', 'type': 'str'},
        'arguments': {'key': 'arguments', 'type': '[Argument]'},
        'target': {'key': 'target', 'type': 'str'},
        'values': {'key': 'values', 'type': '[SetValue]'},
        'update_trigger_token': {'key': 'updateTriggerToken', 'type': 'str'},
    }

    def __init__(self, *, context_path: str=None, file: str=None, arguments=None, target: str=None, values=None, update_trigger_token: str=None, **kwargs) -> None:
        super(OverrideTaskStepProperties, self).__init__(**kwargs)
        self.context_path = context_path
        self.file = file
        self.arguments = arguments
        self.target = target
        self.values = values
        self.update_trigger_token = update_trigger_token
