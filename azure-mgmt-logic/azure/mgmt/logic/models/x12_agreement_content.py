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


class X12AgreementContent(Model):
    """The X12 agreement content.

    All required parameters must be populated in order to send to Azure.

    :param receive_agreement: Required. The X12 one-way receive agreement.
    :type receive_agreement: ~azure.mgmt.logic.models.X12OneWayAgreement
    :param send_agreement: Required. The X12 one-way send agreement.
    :type send_agreement: ~azure.mgmt.logic.models.X12OneWayAgreement
    """

    _validation = {
        'receive_agreement': {'required': True},
        'send_agreement': {'required': True},
    }

    _attribute_map = {
        'receive_agreement': {'key': 'receiveAgreement', 'type': 'X12OneWayAgreement'},
        'send_agreement': {'key': 'sendAgreement', 'type': 'X12OneWayAgreement'},
    }

    def __init__(self, **kwargs):
        super(X12AgreementContent, self).__init__(**kwargs)
        self.receive_agreement = kwargs.get('receive_agreement', None)
        self.send_agreement = kwargs.get('send_agreement', None)
