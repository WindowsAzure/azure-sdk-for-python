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


class AccessUri(Model):
    """A disk access SAS uri.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar access_sas: A SAS uri for accessing a disk.
    :vartype access_sas: str
    """

    _validation = {
        'access_sas': {'readonly': True},
    }

    _attribute_map = {
        'access_sas': {'key': 'properties.output.accessSAS', 'type': 'str'},
    }

    def __init__(self):
        self.access_sas = None
