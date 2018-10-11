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


class WebhookUpdateParameters(Model):
    """The parameters supplied to the update webhook operation.

    :param name: Gets or sets the name of the webhook.
    :type name: str
    :param is_enabled: Gets or sets the value of the enabled flag of webhook.
    :type is_enabled: bool
    :param run_on: Gets or sets the name of the hybrid worker group the
     webhook job will run on.
    :type run_on: str
    :param parameters: Gets or sets the parameters of the job.
    :type parameters: dict[str, str]
    :param description: Gets or sets the description of the webhook.
    :type description: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'is_enabled': {'key': 'properties.isEnabled', 'type': 'bool'},
        'run_on': {'key': 'properties.runOn', 'type': 'str'},
        'parameters': {'key': 'properties.parameters', 'type': '{str}'},
        'description': {'key': 'properties.description', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, is_enabled: bool=None, run_on: str=None, parameters=None, description: str=None, **kwargs) -> None:
        super(WebhookUpdateParameters, self).__init__(**kwargs)
        self.name = name
        self.is_enabled = is_enabled
        self.run_on = run_on
        self.parameters = parameters
        self.description = description
