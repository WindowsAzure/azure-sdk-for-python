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


class IntegrationAccountAgreementFilter(Model):
    """The integration account agreement filter for odata query.

    All required parameters must be populated in order to send to Azure.

    :param agreement_type: Required. The agreement type of integration account
     agreement. Possible values include: 'NotSpecified', 'AS2', 'X12',
     'Edifact'
    :type agreement_type: str or ~azure.mgmt.logic.models.AgreementType
    """

    _validation = {
        'agreement_type': {'required': True},
    }

    _attribute_map = {
        'agreement_type': {'key': 'agreementType', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(IntegrationAccountAgreementFilter, self).__init__(**kwargs)
        self.agreement_type = kwargs.get('agreement_type', None)
