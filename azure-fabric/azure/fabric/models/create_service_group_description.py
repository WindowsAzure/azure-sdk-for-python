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


class CreateServiceGroupDescription(Model):
    """The description of the create service group.

    :param application_name:
    :type application_name: str
    :param service_name:
    :type service_name: str
    :param service_type_name:
    :type service_type_name: str
    :param partition_description:
    :type partition_description: :class:`PartitionDescription
     <azure.fabric.models.PartitionDescription>`
    :param placement_constraints:
    :type placement_constraints: str
    :param correlation_scheme:
    :type correlation_scheme: :class:`ServiceCorrelationDescription
     <azure.fabric.models.ServiceCorrelationDescription>`
    :param service_load_metrics:
    :type service_load_metrics: :class:`ServiceCorrelationDescription
     <azure.fabric.models.ServiceCorrelationDescription>`
    :param service_placement_policies:
    :type service_placement_policies: :class:`ServiceCorrelationDescription
     <azure.fabric.models.ServiceCorrelationDescription>`
    :param flags:
    :type flags: int
    :param service_group_member_description:
    :type service_group_member_description: list of
     :class:`ServiceGroupMemberDescription
     <azure.fabric.models.ServiceGroupMemberDescription>`
    :param service_kind: Polymorphic Discriminator
    :type service_kind: str
    """

    _validation = {
        'service_kind': {'required': True},
    }

    _attribute_map = {
        'application_name': {'key': 'ApplicationName', 'type': 'str'},
        'service_name': {'key': 'ServiceName', 'type': 'str'},
        'service_type_name': {'key': 'ServiceTypeName', 'type': 'str'},
        'partition_description': {'key': 'PartitionDescription', 'type': 'PartitionDescription'},
        'placement_constraints': {'key': 'PlacementConstraints', 'type': 'str'},
        'correlation_scheme': {'key': 'CorrelationScheme', 'type': 'ServiceCorrelationDescription'},
        'service_load_metrics': {'key': 'ServiceLoadMetrics', 'type': 'ServiceCorrelationDescription'},
        'service_placement_policies': {'key': 'ServicePlacementPolicies', 'type': 'ServiceCorrelationDescription'},
        'flags': {'key': 'Flags', 'type': 'int'},
        'service_group_member_description': {'key': 'ServiceGroupMemberDescription', 'type': '[ServiceGroupMemberDescription]'},
        'service_kind': {'key': 'ServiceKind', 'type': 'str'},
    }

    _subtype_map = {
        'service_kind': {'Stateless': 'StatelessCreateServiceGroupDescription', 'Stateful': 'StatefulCreateServiceGroupDescription'}
    }

    def __init__(self, application_name=None, service_name=None, service_type_name=None, partition_description=None, placement_constraints=None, correlation_scheme=None, service_load_metrics=None, service_placement_policies=None, flags=None, service_group_member_description=None):
        self.application_name = application_name
        self.service_name = service_name
        self.service_type_name = service_type_name
        self.partition_description = partition_description
        self.placement_constraints = placement_constraints
        self.correlation_scheme = correlation_scheme
        self.service_load_metrics = service_load_metrics
        self.service_placement_policies = service_placement_policies
        self.flags = flags
        self.service_group_member_description = service_group_member_description
        self.service_kind = None
