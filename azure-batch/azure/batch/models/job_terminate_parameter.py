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


class JobTerminateParameter(Model):
    """Options when terminating a job.

    :param terminate_reason: The text you want to appear as the job's
     TerminateReason. The default is 'UserTerminate'.
    :type terminate_reason: str
    """

    _attribute_map = {
        'terminate_reason': {'key': 'terminateReason', 'type': 'str'},
    }

    def __init__(self, terminate_reason=None):
        self.terminate_reason = terminate_reason
