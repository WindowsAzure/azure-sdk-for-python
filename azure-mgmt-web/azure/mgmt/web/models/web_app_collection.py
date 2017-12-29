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


class WebAppCollection(Model):
    """Collection of App Service apps.

    :param value: Collection of resources.
    :type value: list[~azure.mgmt.web.models.Site]
    :param next_link: Link to next page of resources.
    :type next_link: str
    """

    _validation = {
        'value': {'required': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Site]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(self, value, next_link=None):
        super(WebAppCollection, self).__init__()
        self.value = value
        self.next_link = next_link
