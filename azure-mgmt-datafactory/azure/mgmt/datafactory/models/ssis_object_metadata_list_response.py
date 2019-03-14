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


class SsisObjectMetadataListResponse(Model):
    """A list of SSIS object metadata.

    :param value: List of SSIS object metadata.
    :type value: list[~azure.mgmt.datafactory.models.SsisObjectMetadata]
    :param next_link: The link to the next page of results, if any remaining
     results exist.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[SsisObjectMetadata]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(SsisObjectMetadataListResponse, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
        self.next_link = kwargs.get('next_link', None)
