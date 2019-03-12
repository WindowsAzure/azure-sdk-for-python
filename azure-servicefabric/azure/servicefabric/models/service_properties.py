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


class ServiceProperties(Model):
    """Describes properties of a service resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param description: User readable description of the service.
    :type description: str
    :param replica_count: The number of replicas of the service to create.
     Defaults to 1 if not specified.
    :type replica_count: int
    :param auto_scaling_policies: Auto scaling policies
    :type auto_scaling_policies:
     list[~azure.servicefabric.models.AutoScalingPolicy]
    :ivar status: Status of the service. Possible values include: 'Unknown',
     'Ready', 'Upgrading', 'Creating', 'Deleting', 'Failed'
    :vartype status: str or ~azure.servicefabric.models.ResourceStatus
    :ivar status_details: Gives additional information about the current
     status of the service.
    :vartype status_details: str
    :ivar health_state: Describes the health state of an application resource.
     Possible values include: 'Invalid', 'Ok', 'Warning', 'Error', 'Unknown'
    :vartype health_state: str or ~azure.servicefabric.models.HealthState
    :ivar unhealthy_evaluation: When the service's health state is not 'Ok',
     this additional details from service fabric Health Manager for the user to
     know why the service is marked unhealthy.
    :vartype unhealthy_evaluation: str
    """

    _validation = {
        'status': {'readonly': True},
        'status_details': {'readonly': True},
        'health_state': {'readonly': True},
        'unhealthy_evaluation': {'readonly': True},
    }

    _attribute_map = {
        'description': {'key': 'description', 'type': 'str'},
        'replica_count': {'key': 'replicaCount', 'type': 'int'},
        'auto_scaling_policies': {'key': 'autoScalingPolicies', 'type': '[AutoScalingPolicy]'},
        'status': {'key': 'status', 'type': 'str'},
        'status_details': {'key': 'statusDetails', 'type': 'str'},
        'health_state': {'key': 'healthState', 'type': 'str'},
        'unhealthy_evaluation': {'key': 'unhealthyEvaluation', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ServiceProperties, self).__init__(**kwargs)
        self.description = kwargs.get('description', None)
        self.replica_count = kwargs.get('replica_count', None)
        self.auto_scaling_policies = kwargs.get('auto_scaling_policies', None)
        self.status = None
        self.status_details = None
        self.health_state = None
        self.unhealthy_evaluation = None
