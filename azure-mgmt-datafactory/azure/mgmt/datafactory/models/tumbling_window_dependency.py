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


class TumblingWindowDependency(Model):
    """Tumbling Window dependency information.

    All required parameters must be populated in order to send to Azure.

    :param type: Required. Reference type 'TriggerReference' for Tumbling
     Window.
    :type type: str
    :param reference_name: Required. Trigger reference name.
    :type reference_name: str
    """

    _validation = {
        'type': {'required': True},
        'reference_name': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'reference_name': {'key': 'referenceName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(TumblingWindowDependency, self).__init__(**kwargs)
        self.type = kwargs.get('type', None)
        self.reference_name = kwargs.get('reference_name', None)
