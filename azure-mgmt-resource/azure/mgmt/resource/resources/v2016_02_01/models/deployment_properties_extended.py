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


class DeploymentPropertiesExtended(Model):
    """Deployment properties with additional details.

    :param provisioning_state: The state of the provisioning.
    :type provisioning_state: str
    :param correlation_id: The correlation ID of the deployment.
    :type correlation_id: str
    :param timestamp: The timestamp of the template deployment.
    :type timestamp: datetime
    :param outputs: Key/value pairs that represent deploymentoutput.
    :type outputs: object
    :param providers: The list of resource providers needed for the
     deployment.
    :type providers:
     list[~azure.mgmt.resource.resources.v2016_02_01.models.Provider]
    :param dependencies: The list of deployment dependencies.
    :type dependencies:
     list[~azure.mgmt.resource.resources.v2016_02_01.models.Dependency]
    :param template: The template content. Use only one of Template or
     TemplateLink.
    :type template: object
    :param template_link: The URI referencing the template. Use only one of
     Template or TemplateLink.
    :type template_link:
     ~azure.mgmt.resource.resources.v2016_02_01.models.TemplateLink
    :param parameters: Deployment parameters. Use only one of Parameters or
     ParametersLink.
    :type parameters: object
    :param parameters_link: The URI referencing the parameters. Use only one
     of Parameters or ParametersLink.
    :type parameters_link:
     ~azure.mgmt.resource.resources.v2016_02_01.models.ParametersLink
    :param mode: The deployment mode. Possible values include: 'Incremental',
     'Complete'
    :type mode: str or
     ~azure.mgmt.resource.resources.v2016_02_01.models.DeploymentMode
    :param debug_setting: The debug setting of the deployment.
    :type debug_setting:
     ~azure.mgmt.resource.resources.v2016_02_01.models.DebugSetting
    """

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'correlation_id': {'key': 'correlationId', 'type': 'str'},
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'outputs': {'key': 'outputs', 'type': 'object'},
        'providers': {'key': 'providers', 'type': '[Provider]'},
        'dependencies': {'key': 'dependencies', 'type': '[Dependency]'},
        'template': {'key': 'template', 'type': 'object'},
        'template_link': {'key': 'templateLink', 'type': 'TemplateLink'},
        'parameters': {'key': 'parameters', 'type': 'object'},
        'parameters_link': {'key': 'parametersLink', 'type': 'ParametersLink'},
        'mode': {'key': 'mode', 'type': 'DeploymentMode'},
        'debug_setting': {'key': 'debugSetting', 'type': 'DebugSetting'},
    }

    def __init__(self, **kwargs):
        super(DeploymentPropertiesExtended, self).__init__(**kwargs)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.correlation_id = kwargs.get('correlation_id', None)
        self.timestamp = kwargs.get('timestamp', None)
        self.outputs = kwargs.get('outputs', None)
        self.providers = kwargs.get('providers', None)
        self.dependencies = kwargs.get('dependencies', None)
        self.template = kwargs.get('template', None)
        self.template_link = kwargs.get('template_link', None)
        self.parameters = kwargs.get('parameters', None)
        self.parameters_link = kwargs.get('parameters_link', None)
        self.mode = kwargs.get('mode', None)
        self.debug_setting = kwargs.get('debug_setting', None)
