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


class CreateRunResponse(Model):
    """Response body with a run identifier.

    All required parameters must be populated in order to send to Azure.

    :param run_id: Required. Identifier of a run.
    :type run_id: str
    """

    _validation = {
        'run_id': {'required': True},
    }

    _attribute_map = {
        'run_id': {'key': 'runId', 'type': 'str'},
    }

    def __init__(self, *, run_id: str, **kwargs) -> None:
        super(CreateRunResponse, self).__init__(**kwargs)
        self.run_id = run_id
