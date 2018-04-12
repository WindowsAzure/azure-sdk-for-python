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


class ServiceTypeDescription(Model):
    """Describes a service type defined in the service manifest of a provisioned
    application type. The properties the ones defined in the service manifest.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: StatefulServiceTypeDescription,
    StatelessServiceTypeDescription

    All required parameters must be populated in order to send to Azure.

    :param is_stateful: Indicates whether the service type is a stateful
     service type or a stateless service type. This property is true if the
     service type is a stateful service type, false otherwise.
    :type is_stateful: bool
    :param service_type_name: Name of the service type as specified in the
     service manifest.
    :type service_type_name: str
    :param placement_constraints: The placement constraint to be used when
     instantiating this service in a Service Fabric cluster.
    :type placement_constraints: str
    :param service_placement_policies: List of service placement policy
     descriptions.
    :type service_placement_policies:
     list[~azure.servicefabric.models.ServicePlacementPolicyDescription]
    :param extensions: List of service type extensions.
    :type extensions:
     list[~azure.servicefabric.models.ServiceTypeExtensionDescription]
    :param kind: Required. Constant filled by server.
    :type kind: str
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'is_stateful': {'key': 'IsStateful', 'type': 'bool'},
        'service_type_name': {'key': 'ServiceTypeName', 'type': 'str'},
        'placement_constraints': {'key': 'PlacementConstraints', 'type': 'str'},
        'service_placement_policies': {'key': 'ServicePlacementPolicies', 'type': '[ServicePlacementPolicyDescription]'},
        'extensions': {'key': 'Extensions', 'type': '[ServiceTypeExtensionDescription]'},
        'kind': {'key': 'Kind', 'type': 'str'},
    }

    _subtype_map = {
        'kind': {'Stateful': 'StatefulServiceTypeDescription', 'Stateless': 'StatelessServiceTypeDescription'}
    }

    def __init__(self, **kwargs):
        super(ServiceTypeDescription, self).__init__(**kwargs)
        self.is_stateful = kwargs.get('is_stateful', None)
        self.service_type_name = kwargs.get('service_type_name', None)
        self.placement_constraints = kwargs.get('placement_constraints', None)
        self.service_placement_policies = kwargs.get('service_placement_policies', None)
        self.extensions = kwargs.get('extensions', None)
        self.kind = None
