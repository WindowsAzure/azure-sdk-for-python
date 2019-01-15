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


class RepairImpactDescriptionBase(Model):
    """Describes the expected impact of executing a repair task.
    This type supports the Service Fabric platform; it is not meant to be used
    directly from your code.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: NodeRepairImpactDescription

    All required parameters must be populated in order to send to Azure.

    :param kind: Required. Constant filled by server.
    :type kind: str
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'kind': {'key': 'Kind', 'type': 'str'},
    }

    _subtype_map = {
        'kind': {'Node': 'NodeRepairImpactDescription'}
    }

    def __init__(self, **kwargs) -> None:
        super(RepairImpactDescriptionBase, self).__init__(**kwargs)
        self.kind = None
