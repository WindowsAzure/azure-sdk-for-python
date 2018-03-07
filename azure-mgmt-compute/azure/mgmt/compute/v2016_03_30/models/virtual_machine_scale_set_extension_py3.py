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

from .sub_resource import SubResource


class VirtualMachineScaleSetExtension(SubResource):
    """Describes a Virtual Machine Scale Set Extension.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource Id
    :type id: str
    :param name: The name of the extension.
    :type name: str
    :param publisher: The name of the extension handler publisher.
    :type publisher: str
    :param type: The type of the extension handler.
    :type type: str
    :param type_handler_version: The type version of the extension handler.
    :type type_handler_version: str
    :param auto_upgrade_minor_version: Whether the extension handler should be
     automatically upgraded across minor versions.
    :type auto_upgrade_minor_version: bool
    :param settings: Json formatted public settings for the extension.
    :type settings: object
    :param protected_settings: Json formatted protected settings for the
     extension.
    :type protected_settings: object
    :ivar provisioning_state: The provisioning state, which only appears in
     the response.
    :vartype provisioning_state: str
    """

    _validation = {
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'publisher': {'key': 'properties.publisher', 'type': 'str'},
        'type': {'key': 'properties.type', 'type': 'str'},
        'type_handler_version': {'key': 'properties.typeHandlerVersion', 'type': 'str'},
        'auto_upgrade_minor_version': {'key': 'properties.autoUpgradeMinorVersion', 'type': 'bool'},
        'settings': {'key': 'properties.settings', 'type': 'object'},
        'protected_settings': {'key': 'properties.protectedSettings', 'type': 'object'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, name: str=None, publisher: str=None, type: str=None, type_handler_version: str=None, auto_upgrade_minor_version: bool=None, settings=None, protected_settings=None, **kwargs) -> None:
        super(VirtualMachineScaleSetExtension, self).__init__(id=id, **kwargs)
        self.name = name
        self.publisher = publisher
        self.type = type
        self.type_handler_version = type_handler_version
        self.auto_upgrade_minor_version = auto_upgrade_minor_version
        self.settings = settings
        self.protected_settings = protected_settings
        self.provisioning_state = None
