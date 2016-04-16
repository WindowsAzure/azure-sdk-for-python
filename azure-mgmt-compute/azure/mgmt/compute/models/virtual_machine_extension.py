# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .resource import Resource


class VirtualMachineExtension(Resource):
    """
    Describes a Virtual Machine Extension.

    :param id: Resource Id
    :type id: str
    :param name: Resource name
    :type name: str
    :param type: Resource type
    :type type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict
    :param force_update_tag: Gets or sets how the extension handler should be
     forced to update even if the extension configuration has not changed.
    :type force_update_tag: str
    :param publisher: Gets or sets the name of the extension handler
     publisher.
    :type publisher: str
    :param virtual_machine_extension_type: Gets or sets the type of the
     extension handler.
    :type virtual_machine_extension_type: str
    :param type_handler_version: Gets or sets the type version of the
     extension handler.
    :type type_handler_version: str
    :param auto_upgrade_minor_version: Gets or sets whether the extension
     handler should be automatically upgraded across minor versions.
    :type auto_upgrade_minor_version: bool
    :param settings: Gets or sets Json formatted public settings for the
     extension.
    :type settings: object
    :param protected_settings: Gets or sets Json formatted protected settings
     for the extension.
    :type protected_settings: object
    :param provisioning_state: Gets or sets the provisioning state, which
     only appears in the response.
    :type provisioning_state: str
    :param instance_view: Gets or sets the virtual machine extension instance
     view.
    :type instance_view: :class:`VirtualMachineExtensionInstanceView
     <computemanagementclient.models.VirtualMachineExtensionInstanceView>`
    """ 

    _validation = {
        'location': {'required': True},
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

    def __init__(self, location, id=None, name=None, type=None, tags=None, force_update_tag=None, publisher=None, virtual_machine_extension_type=None, type_handler_version=None, auto_upgrade_minor_version=None, settings=None, protected_settings=None, provisioning_state=None, instance_view=None):
        super(VirtualMachineExtension, self).__init__(id=id, name=name, type=type, location=location, tags=tags)
        self.force_update_tag = force_update_tag
        self.publisher = publisher
        self.virtual_machine_extension_type = virtual_machine_extension_type
        self.type_handler_version = type_handler_version
        self.auto_upgrade_minor_version = auto_upgrade_minor_version
        self.settings = settings
        self.protected_settings = protected_settings
        self.provisioning_state = provisioning_state
        self.instance_view = instance_view
