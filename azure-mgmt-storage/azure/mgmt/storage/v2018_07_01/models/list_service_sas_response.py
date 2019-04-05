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


class ListServiceSasResponse(Model):
    """The List service SAS credentials operation response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar service_sas_token: List service SAS credentials of specific
     resource.
    :vartype service_sas_token: str
    """

    _validation = {
        'service_sas_token': {'readonly': True},
    }

    _attribute_map = {
        'service_sas_token': {'key': 'serviceSasToken', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ListServiceSasResponse, self).__init__(**kwargs)
        self.service_sas_token = None
