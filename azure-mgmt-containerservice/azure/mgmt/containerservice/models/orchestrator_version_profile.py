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


class OrchestratorVersionProfile(Model):
    """The profile of an orchestrator and its available versions.

    All required parameters must be populated in order to send to Azure.

    :param orchestrator_type: Required. Orchestrator type.
    :type orchestrator_type: str
    :param orchestrator_version: Required. Orchestrator version (major, minor,
     patch).
    :type orchestrator_version: str
    :param default: Required. Installed by default if version is not
     specified.
    :type default: bool
    :param upgrades: Required. The list of available upgrade versions.
    :type upgrades:
     list[~azure.mgmt.containerservice.models.OrchestratorProfile]
    """

    _validation = {
        'orchestrator_type': {'required': True},
        'orchestrator_version': {'required': True},
        'default': {'required': True},
        'upgrades': {'required': True},
    }

    _attribute_map = {
        'orchestrator_type': {'key': 'orchestratorType', 'type': 'str'},
        'orchestrator_version': {'key': 'orchestratorVersion', 'type': 'str'},
        'default': {'key': 'default', 'type': 'bool'},
        'upgrades': {'key': 'upgrades', 'type': '[OrchestratorProfile]'},
    }

    def __init__(self, **kwargs):
        super(OrchestratorVersionProfile, self).__init__(**kwargs)
        self.orchestrator_type = kwargs.get('orchestrator_type', None)
        self.orchestrator_version = kwargs.get('orchestrator_version', None)
        self.default = kwargs.get('default', None)
        self.upgrades = kwargs.get('upgrades', None)
