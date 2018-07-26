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


class AzureIaaSVMJobExtendedInfo(Model):
    """Azure IaaS VM workload-specific additional information for job.

    :param tasks_list: List of tasks associated with this job.
    :type tasks_list:
     list[~azure.mgmt.recoveryservicesbackup.models.AzureIaaSVMJobTaskDetails]
    :param property_bag: Job properties.
    :type property_bag: dict[str, str]
    :param internal_property_bag: Job internal properties.
    :type internal_property_bag: dict[str, str]
    :param progress_percentage: Indicates progress of the job. Null if it has
     not started or completed.
    :type progress_percentage: float
    :param dynamic_error_message: Non localized error message on job
     execution.
    :type dynamic_error_message: str
    """

    _attribute_map = {
        'tasks_list': {'key': 'tasksList', 'type': '[AzureIaaSVMJobTaskDetails]'},
        'property_bag': {'key': 'propertyBag', 'type': '{str}'},
        'internal_property_bag': {'key': 'internalPropertyBag', 'type': '{str}'},
        'progress_percentage': {'key': 'progressPercentage', 'type': 'float'},
        'dynamic_error_message': {'key': 'dynamicErrorMessage', 'type': 'str'},
    }

    def __init__(self, *, tasks_list=None, property_bag=None, internal_property_bag=None, progress_percentage: float=None, dynamic_error_message: str=None, **kwargs) -> None:
        super(AzureIaaSVMJobExtendedInfo, self).__init__(**kwargs)
        self.tasks_list = tasks_list
        self.property_bag = property_bag
        self.internal_property_bag = internal_property_bag
        self.progress_percentage = progress_percentage
        self.dynamic_error_message = dynamic_error_message
