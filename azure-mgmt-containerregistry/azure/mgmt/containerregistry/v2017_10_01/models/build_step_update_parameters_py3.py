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


class BuildStepUpdateParameters(Model):
    """The parameters for updating a build step.

    :param properties: The properties for updating a build step.
    :type properties:
     ~azure.mgmt.containerregistry.v2017_10_01.models.BuildStepPropertiesUpdateParameters
    :param tags: The ARM resource tags.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'properties': {'key': 'properties', 'type': 'BuildStepPropertiesUpdateParameters'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, properties=None, tags=None, **kwargs) -> None:
        super(BuildStepUpdateParameters, self).__init__(**kwargs)
        self.properties = properties
        self.tags = tags
