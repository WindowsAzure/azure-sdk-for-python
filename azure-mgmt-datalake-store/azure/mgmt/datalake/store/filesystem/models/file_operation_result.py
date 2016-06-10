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


class FileOperationResult(Model):
    """
    The result of the request or operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar operation_result: the result of the operation or request.
    :vartype operation_result: bool
    """ 

    _validation = {
        'operation_result': {'readonly': True},
    }

    _attribute_map = {
        'operation_result': {'key': 'boolean', 'type': 'bool'},
    }

    def __init__(self):
        self.operation_result = None
