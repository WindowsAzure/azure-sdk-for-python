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


class DscCompilationJobCreateParameters(Model):
    """The parameters supplied to the create compilation job operation.

    All required parameters must be populated in order to send to Azure.

    :param configuration: Required. Gets or sets the configuration.
    :type configuration:
     ~azure.mgmt.automation.models.DscConfigurationAssociationProperty
    :param parameters: Gets or sets the parameters of the job.
    :type parameters: dict[str, str]
    :param increment_node_configuration_build: If a new build version of
     NodeConfiguration is required.
    :type increment_node_configuration_build: bool
    :param name: Gets or sets name of the resource.
    :type name: str
    :param location: Gets or sets the location of the resource.
    :type location: str
    :param tags: Gets or sets the tags attached to the resource.
    :type tags: dict[str, str]
    """

    _validation = {
        'configuration': {'required': True},
    }

    _attribute_map = {
        'configuration': {'key': 'properties.configuration', 'type': 'DscConfigurationAssociationProperty'},
        'parameters': {'key': 'properties.parameters', 'type': '{str}'},
        'increment_node_configuration_build': {'key': 'properties.incrementNodeConfigurationBuild', 'type': 'bool'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(DscCompilationJobCreateParameters, self).__init__(**kwargs)
        self.configuration = kwargs.get('configuration', None)
        self.parameters = kwargs.get('parameters', None)
        self.increment_node_configuration_build = kwargs.get('increment_node_configuration_build', None)
        self.name = kwargs.get('name', None)
        self.location = kwargs.get('location', None)
        self.tags = kwargs.get('tags', None)
