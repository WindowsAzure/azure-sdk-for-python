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


class CatalogItemList(Model):
    """A Data Lake Analytics catalog item list.

    :param count: the count of items in the list.
    :type count: int
    :param next_link: the link to the next page of results.
    :type next_link: str
    """ 

    _attribute_map = {
        'count': {'key': 'count', 'type': 'int'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(self, count=None, next_link=None):
        self.count = count
        self.next_link = next_link
