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


class DependencyReference(Model):
    """Referenced dependency.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: SelfDependencyTumblingWindowTriggerReference,
    TriggerDependencyReference

    All required parameters must be populated in order to send to Azure.

    :param type: Required. Constant filled by server.
    :type type: str
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
    }

    _subtype_map = {
        'type': {'SelfDependencyTumblingWindowTriggerReference': 'SelfDependencyTumblingWindowTriggerReference', 'TriggerDependencyReference': 'TriggerDependencyReference'}
    }

    def __init__(self, **kwargs) -> None:
        super(DependencyReference, self).__init__(**kwargs)
        self.type = None
