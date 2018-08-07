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

    :param name: The name of the script action.
    :type name: str
    :param uri: The URI to the script.
    :type uri: str
    :param parameters: The parameters for the script provided.
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

    def __init__(self, name, uri, parameters):
        super(ScriptAction, self).__init__()
        self.name = name
        self.uri = uri
        self.parameters = parameters
