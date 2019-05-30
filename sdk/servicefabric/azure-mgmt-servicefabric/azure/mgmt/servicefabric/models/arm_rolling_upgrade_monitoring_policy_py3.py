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


class ArmRollingUpgradeMonitoringPolicy(Model):
    """The policy used for monitoring the application upgrade.

    :param failure_action: The activation Mode of the service package.
     Possible values include: 'Rollback', 'Manual'
    :type failure_action: str or
     ~azure.mgmt.servicefabric.models.ArmUpgradeFailureAction
    :param health_check_wait_duration: The amount of time to wait after
     completing an upgrade domain before applying health policies. It is first
     interpreted as a string representing an ISO 8601 duration. If that fails,
     then it is interpreted as a number representing the total number of
     milliseconds.
    :type health_check_wait_duration: str
    :param health_check_stable_duration: The amount of time that the
     application or cluster must remain healthy before the upgrade proceeds to
     the next upgrade domain. It is first interpreted as a string representing
     an ISO 8601 duration. If that fails, then it is interpreted as a number
     representing the total number of milliseconds.
    :type health_check_stable_duration: str
    :param health_check_retry_timeout: The amount of time to retry health
     evaluation when the application or cluster is unhealthy before
     FailureAction is executed. It is first interpreted as a string
     representing an ISO 8601 duration. If that fails, then it is interpreted
     as a number representing the total number of milliseconds.
    :type health_check_retry_timeout: str
    :param upgrade_timeout: The amount of time the overall upgrade has to
     complete before FailureAction is executed. It is first interpreted as a
     string representing an ISO 8601 duration. If that fails, then it is
     interpreted as a number representing the total number of milliseconds.
    :type upgrade_timeout: str
    :param upgrade_domain_timeout: The amount of time each upgrade domain has
     to complete before FailureAction is executed. It is first interpreted as a
     string representing an ISO 8601 duration. If that fails, then it is
     interpreted as a number representing the total number of milliseconds.
    :type upgrade_domain_timeout: str
    """

    _attribute_map = {
        'failure_action': {'key': 'failureAction', 'type': 'str'},
        'health_check_wait_duration': {'key': 'healthCheckWaitDuration', 'type': 'str'},
        'health_check_stable_duration': {'key': 'healthCheckStableDuration', 'type': 'str'},
        'health_check_retry_timeout': {'key': 'healthCheckRetryTimeout', 'type': 'str'},
        'upgrade_timeout': {'key': 'upgradeTimeout', 'type': 'str'},
        'upgrade_domain_timeout': {'key': 'upgradeDomainTimeout', 'type': 'str'},
    }

    def __init__(self, *, failure_action=None, health_check_wait_duration: str=None, health_check_stable_duration: str=None, health_check_retry_timeout: str=None, upgrade_timeout: str=None, upgrade_domain_timeout: str=None, **kwargs) -> None:
        super(ArmRollingUpgradeMonitoringPolicy, self).__init__(**kwargs)
        self.failure_action = failure_action
        self.health_check_wait_duration = health_check_wait_duration
        self.health_check_stable_duration = health_check_stable_duration
        self.health_check_retry_timeout = health_check_retry_timeout
        self.upgrade_timeout = upgrade_timeout
        self.upgrade_domain_timeout = upgrade_domain_timeout
