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


class RollingUpgradeMonitoringPolicy(Model):
    """The policy used for monitoring the application upgrade.

    :param health_check_wait_duration:
    :type health_check_wait_duration: str
    :param health_check_stable_duration:
    :type health_check_stable_duration: str
    :param health_check_retry_timeout:
    :type health_check_retry_timeout: str
    :param upgrade_timeout:
    :type upgrade_timeout: str
    :param upgrade_domain_timeout:
    :type upgrade_domain_timeout: str
    """

    _attribute_map = {
        'health_check_wait_duration': {'key': 'healthCheckWaitDuration', 'type': 'str'},
        'health_check_stable_duration': {'key': 'healthCheckStableDuration', 'type': 'str'},
        'health_check_retry_timeout': {'key': 'healthCheckRetryTimeout', 'type': 'str'},
        'upgrade_timeout': {'key': 'upgradeTimeout', 'type': 'str'},
        'upgrade_domain_timeout': {'key': 'upgradeDomainTimeout', 'type': 'str'},
    }

    def __init__(self, health_check_wait_duration=None, health_check_stable_duration=None, health_check_retry_timeout=None, upgrade_timeout=None, upgrade_domain_timeout=None):
        self.health_check_wait_duration = health_check_wait_duration
        self.health_check_stable_duration = health_check_stable_duration
        self.health_check_retry_timeout = health_check_retry_timeout
        self.upgrade_timeout = upgrade_timeout
        self.upgrade_domain_timeout = upgrade_domain_timeout
