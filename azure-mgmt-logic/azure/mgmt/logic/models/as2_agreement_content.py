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


class AS2AgreementContent(Model):
    """The integration account AS2 agreement content.

    :param receive_agreement: The AS2 one-way receive agreement.
    :type receive_agreement: ~azure.mgmt.logic.models.AS2OneWayAgreement
    :param send_agreement: The AS2 one-way send agreement.
    :type send_agreement: ~azure.mgmt.logic.models.AS2OneWayAgreement
    """

    _validation = {
        'receive_agreement': {'required': True},
        'send_agreement': {'required': True},
    }

    _attribute_map = {
        'receive_agreement': {'key': 'receiveAgreement', 'type': 'AS2OneWayAgreement'},
        'send_agreement': {'key': 'sendAgreement', 'type': 'AS2OneWayAgreement'},
    }

    def __init__(self, receive_agreement, send_agreement):
        super(AS2AgreementContent, self).__init__()
        self.receive_agreement = receive_agreement
        self.send_agreement = send_agreement
