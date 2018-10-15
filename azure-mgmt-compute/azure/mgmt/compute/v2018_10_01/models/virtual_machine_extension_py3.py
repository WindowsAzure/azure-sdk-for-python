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

from .resource_py3 import Resource


class VirtualMachineExtension(Resource):
    """Describes a Virtual Machine Extension.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Required. Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param force_update_tag: How the extension handler should be forced to
     update even if the extension configuration has not changed.
    :type force_update_tag: str
    :param publisher: The name of the extension handler publisher.
    :type publisher: str
    :param virtual_machine_extension_type: Specifies the type of the
     extension; an example is "CustomScriptExtension".
    :type virtual_machine_extension_type: str
    :param type_handler_version: Specifies the version of the script handler.
    :type type_handler_version: str
    :param auto_upgrade_minor_version: Indicates whether the extension should
     use a newer minor version if one is available at deployment time. Once
     deployed, however, the extension will not upgrade minor versions unless
     redeployed, even with this property set to true.
    :type auto_upgrade_minor_version: bool
    :param settings: Json formatted public settings for the extension.
    :type settings: object
    :param protected_settings: The extension can contain either
     protectedSettings or protectedSettingsFromKeyVault or no protected
     settings at all.
    :type protected_settings: object
    :ivar provisioning_state: The provisioning state, which only appears in
     the response.
    :vartype provisioning_state: str
    :param instance_view: The virtual machine extension instance view.
    :type instance_view:
     ~azure.mgmt.compute.v2018_10_01.models.VirtualMachineExtensionInstanceView
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'force_update_tag': {'key': 'properties.forceUpdateTag', 'type': 'str'},
        'publisher': {'key': 'properties.publisher', 'type': 'str'},
        'virtual_machine_extension_type': {'key': 'properties.type', 'type': 'str'},
        'type_handler_version': {'key': 'properties.typeHandlerVersion', 'type': 'str'},
        'auto_upgrade_minor_version': {'key': 'properties.autoUpgradeMinorVersion', 'type': 'bool'},
        'settings': {'key': 'properties.settings', 'type': 'object'},
        'protected_settings': {'key': 'properties.protectedSettings', 'type': 'object'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'instance_view': {'key': 'properties.instanceView', 'type': 'VirtualMachineExtensionInstanceView'},
    }

    def __init__(self, *, location: str, tags=None, force_update_tag: str=None, publisher: str=None, virtual_machine_extension_type: str=None, type_handler_version: str=None, auto_upgrade_minor_version: bool=None, settings=None, protected_settings=None, instance_view=None, **kwargs) -> None:
        super(VirtualMachineExtension, self).__init__(location=location, tags=tags, **kwargs)
        self.force_update_tag = force_update_tag
        self.publisher = publisher
        self.virtual_machine_extension_type = virtual_machine_extension_type
        self.type_handler_version = type_handler_version
        self.auto_upgrade_minor_version = auto_upgrade_minor_version
        self.settings = settings
        self.protected_settings = protected_settings
        self.provisioning_state = None
        self.instance_view = instance_view
