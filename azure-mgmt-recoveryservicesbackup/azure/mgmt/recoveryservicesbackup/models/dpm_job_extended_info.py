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


class DpmJobExtendedInfo(Model):
    """Additional information on the DPM workload-specific job.

    :param tasks_list: List of tasks associated with this job.
    :type tasks_list:
     list[~azure.mgmt.recoveryservicesbackup.models.DpmJobTaskDetails]
    :param property_bag: The job properties.
    :type property_bag: dict[str, str]
    :param dynamic_error_message: Non localized error message on job
     execution.
    :type dynamic_error_message: str
    """

    _attribute_map = {
        'tasks_list': {'key': 'tasksList', 'type': '[DpmJobTaskDetails]'},
        'property_bag': {'key': 'propertyBag', 'type': '{str}'},
        'dynamic_error_message': {'key': 'dynamicErrorMessage', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(DpmJobExtendedInfo, self).__init__(**kwargs)
        self.tasks_list = kwargs.get('tasks_list', None)
        self.property_bag = kwargs.get('property_bag', None)
        self.dynamic_error_message = kwargs.get('dynamic_error_message', None)
