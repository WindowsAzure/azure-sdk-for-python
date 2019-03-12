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


class UpdateIntegrationRuntimeNodeRequest(Model):
    """Update integration runtime node request.

    :param concurrent_jobs_limit: The number of concurrent jobs permitted to
     run on the integration runtime node. Values between 1 and
     maxConcurrentJobs(inclusive) are allowed.
    :type concurrent_jobs_limit: int
    """

    _validation = {
        'concurrent_jobs_limit': {'minimum': 1},
    }

    _attribute_map = {
        'concurrent_jobs_limit': {'key': 'concurrentJobsLimit', 'type': 'int'},
    }

    def __init__(self, concurrent_jobs_limit=None):
        super(UpdateIntegrationRuntimeNodeRequest, self).__init__()
        self.concurrent_jobs_limit = concurrent_jobs_limit
