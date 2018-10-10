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


class NetworkConfigurationDiagnosticResponse(Model):
    """Results of network configuration diagnostic on the target resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar results: List of network configuration diagnostic results.
    :vartype results:
     list[~azure.mgmt.network.v2018_08_01.models.NetworkConfigurationDiagnosticResult]
    """

    _validation = {
        'results': {'readonly': True},
    }

    _attribute_map = {
        'results': {'key': 'results', 'type': '[NetworkConfigurationDiagnosticResult]'},
    }

    def __init__(self, **kwargs) -> None:
        super(NetworkConfigurationDiagnosticResponse, self).__init__(**kwargs)
        self.results = None
