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


class ClusterUpgradeProgress(Model):
    """The progress of the cluster upgrade.

    :param code_version:
    :type code_version: str
    :param config_version:
    :type config_version: str
    :param upgrade_domains:
    :type upgrade_domains: list of str
    :param upgrade_state: Possible values include: 'Invalid',
     'RollingBackInProgress', 'RollingBackCompleted', 'RollingForwardPending',
     'RollingForwardInProgress', 'RollingForwardCompleted'
    :type upgrade_state: str or :class:`enum <azure.fabric.models.enum>`
    :param next_upgrade_domain:
    :type next_upgrade_domain: str
    :param rolling_upgrade_mode: Possible values include: 'Invalid',
     'UnmonitoredAuto', 'UnmonitoredManual', 'Monitored'
    :type rolling_upgrade_mode: str or :class:`enum
     <azure.fabric.models.enum>`
    :param upgrade_duration_in_milliseconds:
    :type upgrade_duration_in_milliseconds: str
    :param upgrade_domain_duration_in_milliseconds:
    :type upgrade_domain_duration_in_milliseconds: str
    :param unhealthy_evaluations:
    :type unhealthy_evaluations: list of :class:`UnhealthyEvaluation
     <azure.fabric.models.UnhealthyEvaluation>`
    :param current_upgrade_domain_progress: The progress of the current
     upgrade domain
    :type current_upgrade_domain_progress:
     :class:`ClusterUpgradeProgressCurrentUpgradeDomainProgress
     <azure.fabric.models.ClusterUpgradeProgressCurrentUpgradeDomainProgress>`
    :param start_timestamp_utc:
    :type start_timestamp_utc: str
    :param failure_timestamp_utc:
    :type failure_timestamp_utc: str
    :param failure_reason: Possible values include: 'Invalid', 'Interrupted',
     'HealthCheck', 'UpgradeDomainTimeout', 'OverallUpgradeTimeout'
    :type failure_reason: str or :class:`enum <azure.fabric.models.enum>`
    :param upgrade_domain_progress_at_failure: The failure of the upgrade
     domain progress at
    :type upgrade_domain_progress_at_failure:
     :class:`ClusterUpgradeProgressUpgradeDomainProgressAtFailure
     <azure.fabric.models.ClusterUpgradeProgressUpgradeDomainProgressAtFailure>`
    """

    _attribute_map = {
        'code_version': {'key': 'CodeVersion', 'type': 'str'},
        'config_version': {'key': 'ConfigVersion', 'type': 'str'},
        'upgrade_domains': {'key': 'UpgradeDomains', 'type': '[str]'},
        'upgrade_state': {'key': 'UpgradeState', 'type': 'str'},
        'next_upgrade_domain': {'key': 'NextUpgradeDomain', 'type': 'str'},
        'rolling_upgrade_mode': {'key': 'RollingUpgradeMode', 'type': 'str'},
        'upgrade_duration_in_milliseconds': {'key': 'UpgradeDurationInMilliseconds', 'type': 'str'},
        'upgrade_domain_duration_in_milliseconds': {'key': 'UpgradeDomainDurationInMilliseconds', 'type': 'str'},
        'unhealthy_evaluations': {'key': 'UnhealthyEvaluations', 'type': '[UnhealthyEvaluation]'},
        'current_upgrade_domain_progress': {'key': 'CurrentUpgradeDomainProgress', 'type': 'ClusterUpgradeProgressCurrentUpgradeDomainProgress'},
        'start_timestamp_utc': {'key': 'StartTimestampUtc', 'type': 'str'},
        'failure_timestamp_utc': {'key': 'FailureTimestampUtc', 'type': 'str'},
        'failure_reason': {'key': 'FailureReason', 'type': 'str'},
        'upgrade_domain_progress_at_failure': {'key': 'UpgradeDomainProgressAtFailure', 'type': 'ClusterUpgradeProgressUpgradeDomainProgressAtFailure'},
    }

    def __init__(self, code_version=None, config_version=None, upgrade_domains=None, upgrade_state=None, next_upgrade_domain=None, rolling_upgrade_mode=None, upgrade_duration_in_milliseconds=None, upgrade_domain_duration_in_milliseconds=None, unhealthy_evaluations=None, current_upgrade_domain_progress=None, start_timestamp_utc=None, failure_timestamp_utc=None, failure_reason=None, upgrade_domain_progress_at_failure=None):
        self.code_version = code_version
        self.config_version = config_version
        self.upgrade_domains = upgrade_domains
        self.upgrade_state = upgrade_state
        self.next_upgrade_domain = next_upgrade_domain
        self.rolling_upgrade_mode = rolling_upgrade_mode
        self.upgrade_duration_in_milliseconds = upgrade_duration_in_milliseconds
        self.upgrade_domain_duration_in_milliseconds = upgrade_domain_duration_in_milliseconds
        self.unhealthy_evaluations = unhealthy_evaluations
        self.current_upgrade_domain_progress = current_upgrade_domain_progress
        self.start_timestamp_utc = start_timestamp_utc
        self.failure_timestamp_utc = failure_timestamp_utc
        self.failure_reason = failure_reason
        self.upgrade_domain_progress_at_failure = upgrade_domain_progress_at_failure
