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


class IntegrationAccountPartnerFilter(Model):
    """The integration account partner filter for odata query.

    All required parameters must be populated in order to send to Azure.

    :param partner_type: Required. The partner type of integration account
     partner. Possible values include: 'NotSpecified', 'B2B'
    :type partner_type: str or ~azure.mgmt.logic.models.PartnerType
    """

    _validation = {
        'partner_type': {'required': True},
    }

    _attribute_map = {
        'partner_type': {'key': 'partnerType', 'type': 'PartnerType'},
    }

    def __init__(self, **kwargs):
        super(IntegrationAccountPartnerFilter, self).__init__(**kwargs)
        self.partner_type = kwargs.get('partner_type', None)
