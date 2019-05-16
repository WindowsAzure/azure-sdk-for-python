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


class RunbookCreateOrUpdateDraftParameters(Model):
    """The parameters supplied to the create or update runbook operation.

    All required parameters must be populated in order to send to Azure.

    :param runbook_content: Required. Content of the Runbook.
    :type runbook_content: str
    """

    _validation = {
        'runbook_content': {'required': True},
    }

    _attribute_map = {
        'runbook_content': {'key': 'runbookContent', 'type': 'str'},
    }

    def __init__(self, *, runbook_content: str, **kwargs) -> None:
        super(RunbookCreateOrUpdateDraftParameters, self).__init__(**kwargs)
        self.runbook_content = runbook_content
