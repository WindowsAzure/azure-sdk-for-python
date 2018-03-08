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


class SasDefinitionCreateParameters(Model):
    """The SAS definition create parameters.

    All required parameters must be populated in order to send to Azure.

    :param parameters: Required. Sas definition creation metadata in the form
     of key-value pairs.
    :type parameters: dict[str, str]
    :param sas_definition_attributes: The attributes of the SAS definition.
    :type sas_definition_attributes:
     ~azure.keyvault.models.SasDefinitionAttributes
    :param tags: Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    """

    _validation = {
        'parameters': {'required': True},
    }

    _attribute_map = {
        'parameters': {'key': 'parameters', 'type': '{str}'},
        'sas_definition_attributes': {'key': 'attributes', 'type': 'SasDefinitionAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(SasDefinitionCreateParameters, self).__init__(**kwargs)
        self.parameters = kwargs.get('parameters', None)
        self.sas_definition_attributes = kwargs.get('sas_definition_attributes', None)
        self.tags = kwargs.get('tags', None)
