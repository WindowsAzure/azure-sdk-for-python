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


class TestJobCreateParameters(Model):
    """The parameters supplied to the create test job operation.

    :param parameters: Gets or sets the parameters of the test job.
    :type parameters: dict[str, str]
    :param run_on: Gets or sets the runOn which specifies the group name where
     the job is to be executed.
    :type run_on: str
    """

    _attribute_map = {
        'parameters': {'key': 'parameters', 'type': '{str}'},
        'run_on': {'key': 'runOn', 'type': 'str'},
    }

    def __init__(self, parameters=None, run_on=None):
        super(TestJobCreateParameters, self).__init__()
        self.parameters = parameters
        self.run_on = run_on
