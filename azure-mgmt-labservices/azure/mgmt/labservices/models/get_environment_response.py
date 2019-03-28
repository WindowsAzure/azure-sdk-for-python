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


class GetEnvironmentResponse(Model):
    """Represents the environments details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar environment: Details of the environment
    :vartype environment: ~azure.mgmt.labservices.models.EnvironmentDetails
    """

    _validation = {
        'environment': {'readonly': True},
    }

    _attribute_map = {
        'environment': {'key': 'environment', 'type': 'EnvironmentDetails'},
    }

    def __init__(self, **kwargs):
        super(GetEnvironmentResponse, self).__init__(**kwargs)
        self.environment = None
