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

from msrest.paging import Paged


class AvailabilitySetPaged(Paged):
    """
    A paging container for iterating over a list of :class:`AvailabilitySet <azure.mgmt.compute.v2016_03_30.models.AvailabilitySet>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[AvailabilitySet]'}
    }

    def __init__(self, *args, **kwargs):

        super(AvailabilitySetPaged, self).__init__(*args, **kwargs)
class VirtualMachineSizePaged(Paged):
    """
    A paging container for iterating over a list of :class:`VirtualMachineSize <azure.mgmt.compute.v2016_03_30.models.VirtualMachineSize>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[VirtualMachineSize]'}
    }

    def __init__(self, *args, **kwargs):

        super(VirtualMachineSizePaged, self).__init__(*args, **kwargs)
class VirtualMachinePaged(Paged):
    """
    A paging container for iterating over a list of :class:`VirtualMachine <azure.mgmt.compute.v2016_03_30.models.VirtualMachine>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[VirtualMachine]'}
    }

    def __init__(self, *args, **kwargs):

        super(VirtualMachinePaged, self).__init__(*args, **kwargs)
class UsagePaged(Paged):
    """
    A paging container for iterating over a list of :class:`Usage <azure.mgmt.compute.v2016_03_30.models.Usage>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Usage]'}
    }

    def __init__(self, *args, **kwargs):

        super(UsagePaged, self).__init__(*args, **kwargs)
class VirtualMachineScaleSetPaged(Paged):
    """
    A paging container for iterating over a list of :class:`VirtualMachineScaleSet <azure.mgmt.compute.v2016_03_30.models.VirtualMachineScaleSet>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[VirtualMachineScaleSet]'}
    }

    def __init__(self, *args, **kwargs):

        super(VirtualMachineScaleSetPaged, self).__init__(*args, **kwargs)
class VirtualMachineScaleSetSkuPaged(Paged):
    """
    A paging container for iterating over a list of :class:`VirtualMachineScaleSetSku <azure.mgmt.compute.v2016_03_30.models.VirtualMachineScaleSetSku>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[VirtualMachineScaleSetSku]'}
    }

    def __init__(self, *args, **kwargs):

        super(VirtualMachineScaleSetSkuPaged, self).__init__(*args, **kwargs)
class VirtualMachineScaleSetVMPaged(Paged):
    """
    A paging container for iterating over a list of :class:`VirtualMachineScaleSetVM <azure.mgmt.compute.v2016_03_30.models.VirtualMachineScaleSetVM>` object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[VirtualMachineScaleSetVM]'}
    }

    def __init__(self, *args, **kwargs):

        super(VirtualMachineScaleSetVMPaged, self).__init__(*args, **kwargs)
