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


class MonitoringPolicyDescription(Model):
    """Describes the parameters for monitoring an upgrade in Monitored mode.

    :param failure_action: The compensating action to perform when a Monitored
     upgrade encounters monitoring policy or health policy violations.
     Invalid indicates the failure action is invalid. Rollback specifies that
     the upgrade will start rolling back automatically.
     Manual indicates that the upgrade will switch to UnmonitoredManual upgrade
     mode.
     . Possible values include: 'Invalid', 'Rollback', 'Manual'
    :type failure_action: str or ~azure.servicefabric.models.FailureAction
    :param health_check_wait_duration_in_milliseconds: The amount of time to
     wait after completing an upgrade domain before applying health policies.
     It is first interpreted as a string representing an ISO 8601 duration. If
     that fails, then it is interpreted as a number representing the total
     number of milliseconds.
    :type health_check_wait_duration_in_milliseconds: str
    :param health_check_stable_duration_in_milliseconds: The amount of time
     that the application or cluster must remain healthy before the upgrade
     proceeds to the next upgrade domain. It is first interpreted as a string
     representing an ISO 8601 duration. If that fails, then it is interpreted
     as a number representing the total number of milliseconds.
    :type health_check_stable_duration_in_milliseconds: str
    :param health_check_retry_timeout_in_milliseconds: The amount of time to
     retry health evaluation when the application or cluster is unhealthy
     before FailureAction is executed. It is first interpreted as a string
     representing an ISO 8601 duration. If that fails, then it is interpreted
     as a number representing the total number of milliseconds.
    :type health_check_retry_timeout_in_milliseconds: str
    :param upgrade_timeout_in_milliseconds: The amount of time the overall
     upgrade has to complete before FailureAction is executed. It is first
     interpreted as a string representing an ISO 8601 duration. If that fails,
     then it is interpreted as a number representing the total number of
     milliseconds.
    :type upgrade_timeout_in_milliseconds: str
    :param upgrade_domain_timeout_in_milliseconds: The amount of time each
     upgrade domain has to complete before FailureAction is executed. It is
     first interpreted as a string representing an ISO 8601 duration. If that
     fails, then it is interpreted as a number representing the total number of
     milliseconds.
    :type upgrade_domain_timeout_in_milliseconds: str
    """

    _attribute_map = {
        'failure_action': {'key': 'FailureAction', 'type': 'str'},
        'health_check_wait_duration_in_milliseconds': {'key': 'HealthCheckWaitDurationInMilliseconds', 'type': 'str'},
        'health_check_stable_duration_in_milliseconds': {'key': 'HealthCheckStableDurationInMilliseconds', 'type': 'str'},
        'health_check_retry_timeout_in_milliseconds': {'key': 'HealthCheckRetryTimeoutInMilliseconds', 'type': 'str'},
        'upgrade_timeout_in_milliseconds': {'key': 'UpgradeTimeoutInMilliseconds', 'type': 'str'},
        'upgrade_domain_timeout_in_milliseconds': {'key': 'UpgradeDomainTimeoutInMilliseconds', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(MonitoringPolicyDescription, self).__init__(**kwargs)
        self.failure_action = kwargs.get('failure_action', None)
        self.health_check_wait_duration_in_milliseconds = kwargs.get('health_check_wait_duration_in_milliseconds', None)
        self.health_check_stable_duration_in_milliseconds = kwargs.get('health_check_stable_duration_in_milliseconds', None)
        self.health_check_retry_timeout_in_milliseconds = kwargs.get('health_check_retry_timeout_in_milliseconds', None)
        self.upgrade_timeout_in_milliseconds = kwargs.get('upgrade_timeout_in_milliseconds', None)
        self.upgrade_domain_timeout_in_milliseconds = kwargs.get('upgrade_domain_timeout_in_milliseconds', None)
