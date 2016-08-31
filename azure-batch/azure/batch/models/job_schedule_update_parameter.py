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


class JobScheduleUpdateParameter(Model):
    """Parameters for a CloudJobScheduleOperations.Update request.

    :param schedule: The schedule according to which jobs will be created. If
     you do not specify this element, it is equivalent to passing the default
     schedule: that is, a single job scheduled to run immediately.
    :type schedule: :class:`Schedule <azure.batch.models.Schedule>`
    :param job_specification: Details of the jobs to be created on this
     schedule.
    :type job_specification: :class:`JobSpecification
     <azure.batch.models.JobSpecification>`
    :param metadata: A list of name-value pairs associated with the job
     schedule as metadata. If you do not specify this element, it takes the
     default value of an empty list; in effect, any existing metadata is
     deleted.
    :type metadata: list of :class:`MetadataItem
     <azure.batch.models.MetadataItem>`
    """ 

    _validation = {
        'schedule': {'required': True},
        'job_specification': {'required': True},
    }

    _attribute_map = {
        'schedule': {'key': 'schedule', 'type': 'Schedule'},
        'job_specification': {'key': 'jobSpecification', 'type': 'JobSpecification'},
        'metadata': {'key': 'metadata', 'type': '[MetadataItem]'},
    }

    def __init__(self, schedule, job_specification, metadata=None):
        self.schedule = schedule
        self.job_specification = job_specification
        self.metadata = metadata
