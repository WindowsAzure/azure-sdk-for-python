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

    :param template_uri: Required. The SAS definition token template signed
     with an arbitrary key.  Tokens created according to the SAS definition
     will have the same properties as the template.
    :type template_uri: str
    :param sas_type: Required. The type of SAS token the SAS definition will
     create. Possible values include: 'account', 'service'
    :type sas_type: str or ~azure.keyvault.models.SasTokenType
    :param validity_period: Required. The validity period of SAS tokens
     created according to the SAS definition.
    :type validity_period: str
    :param sas_definition_attributes: The attributes of the SAS definition.
    :type sas_definition_attributes:
     ~azure.keyvault.models.SasDefinitionAttributes
    :param tags: Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    """

    _validation = {
        'template_uri': {'required': True},
        'sas_type': {'required': True},
        'validity_period': {'required': True},
    }

    _attribute_map = {
        'template_uri': {'key': 'templateUri', 'type': 'str'},
        'sas_type': {'key': 'sasType', 'type': 'str'},
        'validity_period': {'key': 'validityPeriod', 'type': 'str'},
        'sas_definition_attributes': {'key': 'attributes', 'type': 'SasDefinitionAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, template_uri: str, sas_type, validity_period: str, sas_definition_attributes=None, tags=None, **kwargs) -> None:
        super(SasDefinitionCreateParameters, self).__init__(**kwargs)
        self.template_uri = template_uri
        self.sas_type = sas_type
        self.validity_period = validity_period
        self.sas_definition_attributes = sas_definition_attributes
        self.tags = tags
