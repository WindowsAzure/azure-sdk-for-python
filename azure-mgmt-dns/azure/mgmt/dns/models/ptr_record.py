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


class PtrRecord(Model):
    """A PTR record.

    :param ptrdname: The PTR target domain name for this PTR record.
    :type ptrdname: str
    """ 

    _attribute_map = {
        'ptrdname': {'key': 'ptrdname', 'type': 'str'},
    }

    def __init__(self, ptrdname=None):
        self.ptrdname = ptrdname
