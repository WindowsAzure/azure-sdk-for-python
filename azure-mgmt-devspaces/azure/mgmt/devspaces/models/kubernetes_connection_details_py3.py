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

from .orchestrator_specific_connection_details_py3 import OrchestratorSpecificConnectionDetails


class KubernetesConnectionDetails(OrchestratorSpecificConnectionDetails):
    """Contains information used to connect to a Kubernetes cluster.

    All required parameters must be populated in order to send to Azure.

    :param instance_type: Required. Constant filled by server.
    :type instance_type: str
    :param kube_config: Gets the kubeconfig for the cluster.
    :type kube_config: str
    """

    _validation = {
        'instance_type': {'required': True},
    }

    _attribute_map = {
        'instance_type': {'key': 'instanceType', 'type': 'str'},
        'kube_config': {'key': 'kubeConfig', 'type': 'str'},
    }

    def __init__(self, *, kube_config: str=None, **kwargs) -> None:
        super(KubernetesConnectionDetails, self).__init__(**kwargs)
        self.kube_config = kube_config
        self.instance_type = 'Kubernetes'
