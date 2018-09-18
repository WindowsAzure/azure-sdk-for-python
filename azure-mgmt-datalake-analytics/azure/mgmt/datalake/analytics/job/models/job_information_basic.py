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


class JobInformationBasic(Model):
    """The common Data Lake Analytics job information properties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar job_id: The job's unique identifier (a GUID).
    :vartype job_id: str
    :param name: Required. The friendly name of the job.
    :type name: str
    :param type: Required. The job type of the current job (Hive, USql, or
     Scope (for internal use only)). Possible values include: 'USql', 'Hive',
     'Scope'
    :type type: str or ~azure.mgmt.datalake.analytics.job.models.JobType
    :ivar submitter: The user or account that submitted the job.
    :vartype submitter: str
    :param degree_of_parallelism: The degree of parallelism used for this job.
     Default value: 1 .
    :type degree_of_parallelism: int
    :ivar degree_of_parallelism_percent: the degree of parallelism in
     percentage used for this job.
    :vartype degree_of_parallelism_percent: float
    :param priority: The priority value for the current job. Lower numbers
     have a higher priority. By default, a job has a priority of 1000. This
     must be greater than 0.
    :type priority: int
    :ivar submit_time: The time the job was submitted to the service.
    :vartype submit_time: datetime
    :ivar start_time: The start time of the job.
    :vartype start_time: datetime
    :ivar end_time: The completion time of the job.
    :vartype end_time: datetime
    :ivar state: The job state. When the job is in the Ended state, refer to
     Result and ErrorMessage for details. Possible values include: 'Accepted',
     'Compiling', 'Ended', 'New', 'Queued', 'Running', 'Scheduling',
     'Starting', 'Paused', 'WaitingForCapacity'
    :vartype state: str or ~azure.mgmt.datalake.analytics.job.models.JobState
    :ivar result: The result of job execution or the current result of the
     running job. Possible values include: 'None', 'Succeeded', 'Cancelled',
     'Failed'
    :vartype result: str or
     ~azure.mgmt.datalake.analytics.job.models.JobResult
    :ivar log_folder: The log folder path to use in the following format:
     adl://<accountName>.azuredatalakestore.net/system/jobservice/jobs/Usql/2016/03/13/17/18/5fe51957-93bc-4de0-8ddc-c5a4753b068b/logs/.
    :vartype log_folder: str
    :param log_file_patterns: The list of log file name patterns to find in
     the logFolder. '*' is the only matching character allowed. Example format:
     jobExecution*.log or *mylog*.txt
    :type log_file_patterns: list[str]
    :param related: The recurring job relationship information properties.
    :type related:
     ~azure.mgmt.datalake.analytics.job.models.JobRelationshipProperties
    :param tags: The key-value pairs used to add additional metadata to the
     job information. (Only for use internally with Scope job type.)
    :type tags: dict[str, str]
    :ivar hierarchy_queue_node: the name of hierarchy queue node this job is
     assigned to, null if job has not been assigned yet or the account doesn't
     have hierarchy queue.
    :vartype hierarchy_queue_node: str
    """

    _validation = {
        'job_id': {'readonly': True},
        'name': {'required': True},
        'type': {'required': True},
        'submitter': {'readonly': True},
        'degree_of_parallelism_percent': {'readonly': True},
        'submit_time': {'readonly': True},
        'start_time': {'readonly': True},
        'end_time': {'readonly': True},
        'state': {'readonly': True},
        'result': {'readonly': True},
        'log_folder': {'readonly': True},
        'hierarchy_queue_node': {'readonly': True},
    }

    _attribute_map = {
        'job_id': {'key': 'jobId', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'JobType'},
        'submitter': {'key': 'submitter', 'type': 'str'},
        'degree_of_parallelism': {'key': 'degreeOfParallelism', 'type': 'int'},
        'degree_of_parallelism_percent': {'key': 'degreeOfParallelismPercent', 'type': 'float'},
        'priority': {'key': 'priority', 'type': 'int'},
        'submit_time': {'key': 'submitTime', 'type': 'iso-8601'},
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'end_time': {'key': 'endTime', 'type': 'iso-8601'},
        'state': {'key': 'state', 'type': 'JobState'},
        'result': {'key': 'result', 'type': 'JobResult'},
        'log_folder': {'key': 'logFolder', 'type': 'str'},
        'log_file_patterns': {'key': 'logFilePatterns', 'type': '[str]'},
        'related': {'key': 'related', 'type': 'JobRelationshipProperties'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'hierarchy_queue_node': {'key': 'hierarchyQueueNode', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(JobInformationBasic, self).__init__(**kwargs)
        self.job_id = None
        self.name = kwargs.get('name', None)
        self.type = kwargs.get('type', None)
        self.submitter = None
        self.degree_of_parallelism = kwargs.get('degree_of_parallelism', 1)
        self.degree_of_parallelism_percent = None
        self.priority = kwargs.get('priority', None)
        self.submit_time = None
        self.start_time = None
        self.end_time = None
        self.state = None
        self.result = None
        self.log_folder = None
        self.log_file_patterns = kwargs.get('log_file_patterns', None)
        self.related = kwargs.get('related', None)
        self.tags = kwargs.get('tags', None)
        self.hierarchy_queue_node = None
