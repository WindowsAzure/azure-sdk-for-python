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


class GenerateArmTemplateRequest(Model):
    """Parameters for generating an ARM template for deploying artifacts.

    :param virtual_machine_name: The resource name of the virtual machine.
    :type virtual_machine_name: str
    :param parameters: The parameters of the ARM template.
    :type parameters: list of :class:`ParameterInfo
     <azure.mgmt.devtestlabs.models.ParameterInfo>`
    :param location: The location of the virtual machine.
    :type location: str
    """ 

    _attribute_map = {
        'virtual_machine_name': {'key': 'virtualMachineName', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '[ParameterInfo]'},
        'location': {'key': 'location', 'type': 'str'},
    }

    def __init__(self, virtual_machine_name=None, parameters=None, location=None):
        self.virtual_machine_name = virtual_machine_name
        self.parameters = parameters
        self.location = location
