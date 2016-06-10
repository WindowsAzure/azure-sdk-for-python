# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class AzureAsyncOperationResult(Model):
    """
    The response body contains the status of the specified asynchronous
    operation, indicating whether it has succeeded, is inprogress, or has
    failed. Note that this status is distinct from the HTTP status code
    returned for the Get Operation Status operation itself. If the
    asynchronous operation succeeded, the response body includes the HTTP
    status code for the successful request. If the asynchronous operation
    failed, the response body includes the HTTP status code for the failed
    request and error information regarding the failure.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar status: the status of the AzureAsuncOperation. Possible values
     include: 'InProgress', 'Succeeded', 'Failed'
    :vartype status: str or :class:`OperationStatus
     <azure.mgmt.datalake.analytics.account.models.OperationStatus>`
    :ivar error:
    :vartype error: :class:`Error
     <azure.mgmt.datalake.analytics.account.models.Error>`
    """ 

    _validation = {
        'status': {'readonly': True},
        'error': {'readonly': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'OperationStatus'},
        'error': {'key': 'error', 'type': 'Error'},
    }

    def __init__(self):
        self.status = None
        self.error = None
