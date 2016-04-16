# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class VirtualMachineScaleSetExtensionProfile(Model):
    """
    Describes a virtual machine scale set extension profile.

    :param extensions: Gets the virtual machine scale set child extension
     resources.
    :type extensions: list of :class:`VirtualMachineScaleSetExtension
     <computemanagementclient.models.VirtualMachineScaleSetExtension>`
    """ 

    _attribute_map = {
        'extensions': {'key': 'extensions', 'type': '[VirtualMachineScaleSetExtension]'},
    }

    def __init__(self, extensions=None):
        self.extensions = extensions
