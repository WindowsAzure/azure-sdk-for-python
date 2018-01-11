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

from .create_job_parameters import CreateJobParameters


class CreateScopeJobParameters(CreateJobParameters):
    """The parameters used to submit a new Data Lake Analytics Scope job. (Only
    for use internally with Scope job type.).

    :param type: the job type of the current job (Hive, USql, or Scope (for
     internal use only)). Possible values include: 'USql', 'Hive', 'Scope'
    :type type: str or ~azure.mgmt.datalake.analytics.job.models.JobType
    :param properties: the job specific properties.
    :type properties:
     ~azure.mgmt.datalake.analytics.job.models.CreateJobProperties
    :param name: the friendly name of the job to submit.
    :type name: str
    :param degree_of_parallelism: the degree of parallelism to use for this
     job. This must be greater than 0, if set to less than 0 it will default to
     1. Default value: 1 .
    :type degree_of_parallelism: int
    :param priority: the priority value to use for the current job. Lower
     numbers have a higher priority. By default, a job has a priority of 1000.
     This must be greater than 0.
    :type priority: int
    :param log_file_patterns: the list of log file name patterns to find in
     the logFolder. '*' is the only matching character allowed. Example format:
     jobExecution*.log or *mylog*.txt
    :type log_file_patterns: list[str]
    :param related: the recurring job relationship information properties.
    :type related:
     ~azure.mgmt.datalake.analytics.job.models.JobRelationshipProperties
    :param tags: the key-value pairs used to add additional metadata to the
     job information. (Only for use internally with Scope job type.)
    :type tags: dict[str, str]
    """

    _validation = {
        'type': {'required': True},
        'properties': {'required': True},
        'name': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'JobType'},
        'properties': {'key': 'properties', 'type': 'CreateJobProperties'},
        'name': {'key': 'name', 'type': 'str'},
        'degree_of_parallelism': {'key': 'degreeOfParallelism', 'type': 'int'},
        'priority': {'key': 'priority', 'type': 'int'},
        'log_file_patterns': {'key': 'logFilePatterns', 'type': '[str]'},
        'related': {'key': 'related', 'type': 'JobRelationshipProperties'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, type, properties, name, degree_of_parallelism=1, priority=None, log_file_patterns=None, related=None, tags=None):
        super(CreateScopeJobParameters, self).__init__(type=type, properties=properties, name=name, degree_of_parallelism=degree_of_parallelism, priority=priority, log_file_patterns=log_file_patterns, related=related)
        self.tags = tags
