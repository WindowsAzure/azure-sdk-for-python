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


class ArmApplicationHealthPolicy(Model):
    """Defines a health policy used to evaluate the health of an application or
    one of its children entities.
    .

    :param consider_warning_as_error: Indicates whether warnings are treated
     with the same severity as errors. Default value: False .
    :type consider_warning_as_error: bool
    :param max_percent_unhealthy_deployed_applications: The maximum allowed
     percentage of unhealthy deployed applications. Allowed values are Byte
     values from zero to 100.
     The percentage represents the maximum tolerated percentage of deployed
     applications that can be unhealthy before the application is considered in
     error.
     This is calculated by dividing the number of unhealthy deployed
     applications over the number of nodes where the application is currently
     deployed on in the cluster.
     The computation rounds up to tolerate one failure on small numbers of
     nodes. Default percentage is zero.
     . Default value: 0 .
    :type max_percent_unhealthy_deployed_applications: int
    :param default_service_type_health_policy: The health policy used by
     default to evaluate the health of a service type.
    :type default_service_type_health_policy:
     ~azure.mgmt.servicefabric.models.ArmServiceTypeHealthPolicy
    :param service_type_health_policy_map: The map with service type health
     policy per service type name. The map is empty by default.
    :type service_type_health_policy_map: dict[str,
     ~azure.mgmt.servicefabric.models.ArmServiceTypeHealthPolicy]
    """

    _attribute_map = {
        'consider_warning_as_error': {'key': 'considerWarningAsError', 'type': 'bool'},
        'max_percent_unhealthy_deployed_applications': {'key': 'maxPercentUnhealthyDeployedApplications', 'type': 'int'},
        'default_service_type_health_policy': {'key': 'defaultServiceTypeHealthPolicy', 'type': 'ArmServiceTypeHealthPolicy'},
        'service_type_health_policy_map': {'key': 'serviceTypeHealthPolicyMap', 'type': '{ArmServiceTypeHealthPolicy}'},
    }

    def __init__(self, *, consider_warning_as_error: bool=False, max_percent_unhealthy_deployed_applications: int=0, default_service_type_health_policy=None, service_type_health_policy_map=None, **kwargs) -> None:
        super(ArmApplicationHealthPolicy, self).__init__(**kwargs)
        self.consider_warning_as_error = consider_warning_as_error
        self.max_percent_unhealthy_deployed_applications = max_percent_unhealthy_deployed_applications
        self.default_service_type_health_policy = default_service_type_health_policy
        self.service_type_health_policy_map = service_type_health_policy_map
