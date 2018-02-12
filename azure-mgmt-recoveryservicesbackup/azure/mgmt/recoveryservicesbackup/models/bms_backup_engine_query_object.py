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


class BMSBackupEngineQueryObject(Model):
    """Query parameters to fetch list of backup engines.

    :param expand: attribute to add extended info
    :type expand: str
    """

    _attribute_map = {
        'expand': {'key': 'expand', 'type': 'str'},
    }

    def __init__(self, expand=None):
        super(BMSBackupEngineQueryObject, self).__init__()
        self.expand = expand
