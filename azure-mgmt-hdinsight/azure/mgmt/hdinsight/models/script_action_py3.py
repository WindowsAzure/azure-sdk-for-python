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


class ScriptAction(Model):
    """Describes a script action on role on the cluster.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the script action.
    :type name: str
    :param uri: Required. The URI to the script.
    :type uri: str
    :param parameters: Required. The parameters for the script provided.
    :type parameters: str
    """

    _validation = {
        'name': {'required': True},
        'uri': {'required': True},
        'parameters': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'uri': {'key': 'uri', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': 'str'},
    }

    def __init__(self, *, name: str, uri: str, parameters: str, **kwargs) -> None:
        super(ScriptAction, self).__init__(**kwargs)
        self.name = name
        self.uri = uri
        self.parameters = parameters
