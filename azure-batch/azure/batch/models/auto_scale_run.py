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


class AutoScaleRun(Model):
    """
    The results and errors from an execution of a pool autoscale formula.

    :param timestamp: Gets or sets the time at which the autoscale formula
     was last evaluated.
    :type timestamp: datetime
    :param results: Gets or sets the final values of all variables used in
     the evaluation of the autoscale formula.  Each variable value is
     returned in the form $variable=value, and variables are separated by
     semicolons.
    :type results: str
    :param error: Gets or sets details of the error encountered evaluating
     the autoscale formula on the pool, if the evaluation was unsuccessful.
    :type error: :class:`AutoScaleRunError
     <batchserviceclient.models.AutoScaleRunError>`
    """ 

    _validation = {
        'timestamp': {'required': True},
    }

    _attribute_map = {
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'results': {'key': 'results', 'type': 'str'},
        'error': {'key': 'error', 'type': 'AutoScaleRunError'},
    }

    def __init__(self, timestamp, results=None, error=None):
        self.timestamp = timestamp
        self.results = results
        self.error = error
