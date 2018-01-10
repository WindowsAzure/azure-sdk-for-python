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


class BaseJobParameters(Model):
    """Data Lake Analytics Job Parameters base class for build and submit.

    :param type: the job type of the current job (Hive, USql, or Scope (for
     internal use only)). Possible values include: 'USql', 'Hive', 'Scope'
    :type type: str or ~azure.mgmt.datalake.analytics.job.models.JobType
    :param properties: the job specific properties.
    :type properties:
     ~azure.mgmt.datalake.analytics.job.models.CreateJobProperties
    """

    _validation = {
        'type': {'required': True},
        'properties': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'JobType'},
        'properties': {'key': 'properties', 'type': 'CreateJobProperties'},
    }

    def __init__(self, type, properties):
        super(BaseJobParameters, self).__init__()
        self.type = type
        self.properties = properties
