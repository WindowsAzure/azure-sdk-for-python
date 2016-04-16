# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class JobSchedulePatchParameter(Model):
    """
    Parameters for a CloudJobScheduleOperations.Patch request.

    :param schedule: Sets the schedule according to which jobs will be
     created. If you do not specify this element, the existing schedule is
     not modified.
    :type schedule: :class:`Schedule <batchserviceclient.models.Schedule>`
    :param job_specification: Sets the details of the jobs to be created on
     this schedule.
    :type job_specification: :class:`JobSpecification
     <batchserviceclient.models.JobSpecification>`
    :param metadata: Sets a list of name-value pairs associated with the job
     schedule as metadata.
    :type metadata: list of :class:`MetadataItem
     <batchserviceclient.models.MetadataItem>`
    """ 

    _attribute_map = {
        'schedule': {'key': 'schedule', 'type': 'Schedule'},
        'job_specification': {'key': 'jobSpecification', 'type': 'JobSpecification'},
        'metadata': {'key': 'metadata', 'type': '[MetadataItem]'},
    }

    def __init__(self, schedule=None, job_specification=None, metadata=None):
        self.schedule = schedule
        self.job_specification = job_specification
        self.metadata = metadata
