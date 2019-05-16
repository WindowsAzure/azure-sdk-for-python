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


class VirtualMachineExtensionInstanceView(Model):
    """The instance view of a virtual machine extension.

    :param name: The virtual machine extension name.
    :type name: str
    :param type: Specifies the type of the extension; an example is
     "CustomScriptExtension".
    :type type: str
    :param type_handler_version: Specifies the version of the script handler.
    :type type_handler_version: str
    :param substatuses: The resource status information.
    :type substatuses:
     list[~azure.mgmt.compute.v2018_04_01.models.InstanceViewStatus]
    :param statuses: The resource status information.
    :type statuses:
     list[~azure.mgmt.compute.v2018_04_01.models.InstanceViewStatus]
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'type_handler_version': {'key': 'typeHandlerVersion', 'type': 'str'},
        'substatuses': {'key': 'substatuses', 'type': '[InstanceViewStatus]'},
        'statuses': {'key': 'statuses', 'type': '[InstanceViewStatus]'},
    }

    def __init__(self, *, name: str=None, type: str=None, type_handler_version: str=None, substatuses=None, statuses=None, **kwargs) -> None:
        super(VirtualMachineExtensionInstanceView, self).__init__(**kwargs)
        self.name = name
        self.type = type
        self.type_handler_version = type_handler_version
        self.substatuses = substatuses
        self.statuses = statuses
