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


class UpdateJobParameters(Model):
    """The parameters that can be used to update existing Data Lake Analytics job
    information properties. (Only for use internally with Scope job type.).

    :param degree_of_parallelism: The degree of parallelism used for this job.
    :type degree_of_parallelism: int
    :param degree_of_parallelism_percent: the degree of parallelism in
     percentage used for this job.
    :type degree_of_parallelism_percent: float
    :param priority: The priority value for the current job. Lower numbers
     have a higher priority. By default, a job has a priority of 1000. This
     must be greater than 0.
    :type priority: int
    :param tags: The key-value pairs used to add additional metadata to the
     job information.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'degree_of_parallelism': {'key': 'degreeOfParallelism', 'type': 'int'},
        'degree_of_parallelism_percent': {'key': 'degreeOfParallelismPercent', 'type': 'float'},
        'priority': {'key': 'priority', 'type': 'int'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(UpdateJobParameters, self).__init__(**kwargs)
        self.degree_of_parallelism = kwargs.get('degree_of_parallelism', None)
        self.degree_of_parallelism_percent = kwargs.get('degree_of_parallelism_percent', None)
        self.priority = kwargs.get('priority', None)
        self.tags = kwargs.get('tags', None)
