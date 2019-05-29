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


class Compute(Model):
    """Compute Metadata.

    :param az_environment: This is the name of the environment in which the VM
     is running.
    :type az_environment: str
    :param location: This is the Azure Region in which the VM is running.
    :type location: str
    :param name: This is the name of the VM.
    :type name: str
    :param offer: This is the offer information for the VM image. This value
     is only present for images deployed from the Azure Image Gallery.
    :type offer: str
    :param os_type: This value indicates the type of OS the VM is running,
     either Linux or Windows.
    :type os_type: str
    :param placement_group_id: This is the placement group of your Virtual
     Machine Scale Set.
    :type placement_group_id: str
    :param plan: This contains the data about the plan.
    :type plan: ~azure.imds.models.PlanProperties
    :param public_keys: This is information about the SSH certificate
    :type public_keys: list[~azure.imds.models.PublicKeysProperties]
    :param platform_fault_domain: This is the fault domain in which the VM.
    :type platform_fault_domain: str
    :param platform_update_domain: This is the update domain in which the VM.
    :type platform_update_domain: str
    :param provider: This is the provider of the VM.
    :type provider: str
    :param publisher: This is the publisher of the VM image.
    :type publisher: str
    :param resource_group_name: This is the resource group for the VM.
    :type resource_group_name: str
    :param sku: This is the specific SKU for the VM image.
    :type sku: str
    :param subscription_id: This is the Azure subscription for the VM.
    :type subscription_id: str
    :param tags: This is the list of tags for your VM.
    :type tags: str
    :param version: This is the version of the VM image.
    :type version: str
    :param vm_id: This is the unique identifier for the VM.
    :type vm_id: str
    :param vm_scale_set_name: This is the resource name of the VMSS.
    :type vm_scale_set_name: str
    :param vm_size: This is the size of the VM.
    :type vm_size: str
    :param zone: This is the availability zone of the VM.
    :type zone: str
    """

    _attribute_map = {
        'az_environment': {'key': 'azEnvironment', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'offer': {'key': 'offer', 'type': 'str'},
        'os_type': {'key': 'osType', 'type': 'str'},
        'placement_group_id': {'key': 'placementGroupId', 'type': 'str'},
        'plan': {'key': 'plan', 'type': 'PlanProperties'},
        'public_keys': {'key': 'publicKeys', 'type': '[PublicKeysProperties]'},
        'platform_fault_domain': {'key': 'platformFaultDomain', 'type': 'str'},
        'platform_update_domain': {'key': 'platformUpdateDomain', 'type': 'str'},
        'provider': {'key': 'provider', 'type': 'str'},
        'publisher': {'key': 'publisher', 'type': 'str'},
        'resource_group_name': {'key': 'resourceGroupName', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'str'},
        'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
        'tags': {'key': 'tags', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
        'vm_id': {'key': 'vmId', 'type': 'str'},
        'vm_scale_set_name': {'key': 'vmScaleSetName', 'type': 'str'},
        'vm_size': {'key': 'vmSize', 'type': 'str'},
        'zone': {'key': 'zone', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Compute, self).__init__(**kwargs)
        self.az_environment = kwargs.get('az_environment', None)
        self.location = kwargs.get('location', None)
        self.name = kwargs.get('name', None)
        self.offer = kwargs.get('offer', None)
        self.os_type = kwargs.get('os_type', None)
        self.placement_group_id = kwargs.get('placement_group_id', None)
        self.plan = kwargs.get('plan', None)
        self.public_keys = kwargs.get('public_keys', None)
        self.platform_fault_domain = kwargs.get('platform_fault_domain', None)
        self.platform_update_domain = kwargs.get('platform_update_domain', None)
        self.provider = kwargs.get('provider', None)
        self.publisher = kwargs.get('publisher', None)
        self.resource_group_name = kwargs.get('resource_group_name', None)
        self.sku = kwargs.get('sku', None)
        self.subscription_id = kwargs.get('subscription_id', None)
        self.tags = kwargs.get('tags', None)
        self.version = kwargs.get('version', None)
        self.vm_id = kwargs.get('vm_id', None)
        self.vm_scale_set_name = kwargs.get('vm_scale_set_name', None)
        self.vm_size = kwargs.get('vm_size', None)
        self.zone = kwargs.get('zone', None)
