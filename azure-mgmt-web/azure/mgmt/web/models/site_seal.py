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


class SiteSeal(Model):
    """Site seal.

    :param html: HTML snippet
    :type html: str
    """

    _validation = {
        'html': {'required': True},
    }

    _attribute_map = {
        'html': {'key': 'html', 'type': 'str'},
    }

    def __init__(self, html):
        self.html = html
