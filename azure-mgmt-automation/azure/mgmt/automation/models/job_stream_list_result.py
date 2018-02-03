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


class JobStreamListResult(Model):
    """The response model for the list job stream operation.

    :param value: A list of job streams.
    :type value: list[~azure.mgmt.automation.models.JobStream]
    :param next_link: Gets or sets the next link.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[JobStream]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(self, value=None, next_link=None):
        super(JobStreamListResult, self).__init__()
        self.value = value
        self.next_link = next_link
