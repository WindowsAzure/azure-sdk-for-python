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


class JobListJsonObject(Model):
    """The List Job operation response.

    :param detail: The detail of the job.
    :type detail: ~azure.hdinsight.job.models.JobDetailRootJsonObject
    :param id: The Id of the job.
    :type id: str
    """

    _attribute_map = {
        'detail': {'key': 'detail', 'type': 'JobDetailRootJsonObject'},
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(JobListJsonObject, self).__init__(**kwargs)
        self.detail = kwargs.get('detail', None)
        self.id = kwargs.get('id', None)
