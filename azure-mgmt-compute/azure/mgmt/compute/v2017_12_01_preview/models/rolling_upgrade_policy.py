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


class RollingUpgradePolicy(Model):
    """The configuration parameters used while performing a rolling upgrade.

    :param max_batch_instance_percent: The maximum percent of total virtual
     machine instances that will be upgraded simultaneously by the rolling
     upgrade in one batch. As this is a maximum, unhealthy instances in
     previous or future batches can cause the percentage of instances in a
     batch to decrease to ensure higher reliability. The default value for this
     parameter is 20%.
    :type max_batch_instance_percent: int
    :param max_unhealthy_instance_percent: The maximum percentage of the total
     virtual machine instances in the scale set that can be simultaneously
     unhealthy, either as a result of being upgraded, or by being found in an
     unhealthy state by the virtual machine health checks before the rolling
     upgrade aborts. This constraint will be checked prior to starting any
     batch. The default value for this parameter is 20%.
    :type max_unhealthy_instance_percent: int
    :param max_unhealthy_upgraded_instance_percent: The maximum percentage of
     upgraded virtual machine instances that can be found to be in an unhealthy
     state. This check will happen after each batch is upgraded. If this
     percentage is ever exceeded, the rolling update aborts. The default value
     for this parameter is 20%.
    :type max_unhealthy_upgraded_instance_percent: int
    :param pause_time_between_batches: The wait time between completing the
     update for all virtual machines in one batch and starting the next batch.
     The time duration should be specified in ISO 8601 format. The default
     value is 0 seconds (PT0S).
    :type pause_time_between_batches: str
    """

    _validation = {
        'max_batch_instance_percent': {'maximum': 100, 'minimum': 5},
        'max_unhealthy_instance_percent': {'maximum': 100, 'minimum': 5},
        'max_unhealthy_upgraded_instance_percent': {'maximum': 100, 'minimum': 0},
    }

    _attribute_map = {
        'max_batch_instance_percent': {'key': 'maxBatchInstancePercent', 'type': 'int'},
        'max_unhealthy_instance_percent': {'key': 'maxUnhealthyInstancePercent', 'type': 'int'},
        'max_unhealthy_upgraded_instance_percent': {'key': 'maxUnhealthyUpgradedInstancePercent', 'type': 'int'},
        'pause_time_between_batches': {'key': 'pauseTimeBetweenBatches', 'type': 'str'},
    }

    def __init__(self, max_batch_instance_percent=None, max_unhealthy_instance_percent=None, max_unhealthy_upgraded_instance_percent=None, pause_time_between_batches=None):
        self.max_batch_instance_percent = max_batch_instance_percent
        self.max_unhealthy_instance_percent = max_unhealthy_instance_percent
        self.max_unhealthy_upgraded_instance_percent = max_unhealthy_upgraded_instance_percent
        self.pause_time_between_batches = pause_time_between_batches
