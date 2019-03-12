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

from .sub_closed_list_py3 import SubClosedList


class SubClosedListResponse(SubClosedList):
    """Sublist of items for a Closed list.

    :param canonical_form: The standard form that the list represents.
    :type canonical_form: str
    :param list: List of synonym words.
    :type list: list[str]
    :param id: The sublist ID
    :type id: int
    """

    _attribute_map = {
        'canonical_form': {'key': 'canonicalForm', 'type': 'str'},
        'list': {'key': 'list', 'type': '[str]'},
        'id': {'key': 'id', 'type': 'int'},
    }

    def __init__(self, *, canonical_form: str=None, list=None, id: int=None, **kwargs) -> None:
        super(SubClosedListResponse, self).__init__(canonical_form=canonical_form, list=list, **kwargs)
        self.id = id
