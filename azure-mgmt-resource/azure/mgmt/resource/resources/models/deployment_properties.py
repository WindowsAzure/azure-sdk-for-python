# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class DeploymentProperties(Model):
    """
    Deployment properties.

    :param template: Gets or sets the template content. Use only one of
     Template or TemplateLink.
    :type template: object
    :param template_link: Gets or sets the URI referencing the template. Use
     only one of Template or TemplateLink.
    :type template_link: :class:`TemplateLink
     <resourcemanagementclient.models.TemplateLink>`
    :param parameters: Deployment parameters. Use only one of Parameters or
     ParametersLink.
    :type parameters: object
    :param parameters_link: Gets or sets the URI referencing the parameters.
     Use only one of Parameters or ParametersLink.
    :type parameters_link: :class:`ParametersLink
     <resourcemanagementclient.models.ParametersLink>`
    :param mode: Gets or sets the deployment mode. Possible values include:
     'Incremental', 'Complete'
    :type mode: str
    :param debug_setting: Gets or sets the debug setting of the deployment.
    :type debug_setting: :class:`DebugSetting
     <resourcemanagementclient.models.DebugSetting>`
    """ 

    _attribute_map = {
        'template': {'key': 'template', 'type': 'object'},
        'template_link': {'key': 'templateLink', 'type': 'TemplateLink'},
        'parameters': {'key': 'parameters', 'type': 'object'},
        'parameters_link': {'key': 'parametersLink', 'type': 'ParametersLink'},
        'mode': {'key': 'mode', 'type': 'DeploymentMode'},
        'debug_setting': {'key': 'debugSetting', 'type': 'DebugSetting'},
    }

    def __init__(self, template=None, template_link=None, parameters=None, parameters_link=None, mode=None, debug_setting=None):
        self.template = template
        self.template_link = template_link
        self.parameters = parameters
        self.parameters_link = parameters_link
        self.mode = mode
        self.debug_setting = debug_setting
