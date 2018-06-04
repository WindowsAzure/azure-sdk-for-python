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


class RunCommandResult(Model):
    """Run command operation response.

    :param output: Operation output data (raw JSON)
    :type output: object
    """

    _attribute_map = {
        'output': {'key': 'properties.output', 'type': 'object'},
    }

    def __init__(self, *, output=None, **kwargs) -> None:
        super(RunCommandResult, self).__init__(**kwargs)
        self.output = output
