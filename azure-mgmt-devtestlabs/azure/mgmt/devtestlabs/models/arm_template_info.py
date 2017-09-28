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


class ArmTemplateInfo(Model):
    """Information about a generated ARM template.

    :param template: The template's contents.
    :type template: object
    :param parameters: The parameters of the ARM template.
    :type parameters: object
    """

    _attribute_map = {
        'template': {'key': 'template', 'type': 'object'},
        'parameters': {'key': 'parameters', 'type': 'object'},
    }

    def __init__(self, template=None, parameters=None):
        self.template = template
        self.parameters = parameters
