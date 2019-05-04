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


class CredentialResults(Model):
    """The list of credential result response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar kubeconfigs: Base64-encoded Kubernetes configuration file.
    :vartype kubeconfigs:
     list[~azure.mgmt.containerservice.v2019_04_01.models.CredentialResult]
    """

    _validation = {
        'kubeconfigs': {'readonly': True},
    }

    _attribute_map = {
        'kubeconfigs': {'key': 'kubeconfigs', 'type': '[CredentialResult]'},
    }

    def __init__(self, **kwargs) -> None:
        super(CredentialResults, self).__init__(**kwargs)
        self.kubeconfigs = None
