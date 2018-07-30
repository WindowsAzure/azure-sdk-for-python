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


class TermsInList(Model):
    """Terms in list Id passed.

    :param term: Added term details.
    :type term: str
    """

    _attribute_map = {
        'term': {'key': 'Term', 'type': 'str'},
    }

    def __init__(self, *, term: str=None, **kwargs) -> None:
        super(TermsInList, self).__init__(**kwargs)
        self.term = term
