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


class TermsOfServiceProperties(Model):
    """Terms of service contract properties.

    :param text: A terms of service text.
    :type text: str
    :param enabled: Display terms of service during a sign-up process.
    :type enabled: bool
    :param consent_required: Ask user for consent to the terms of service.
    :type consent_required: bool
    """

    _attribute_map = {
        'text': {'key': 'text', 'type': 'str'},
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'consent_required': {'key': 'consentRequired', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(TermsOfServiceProperties, self).__init__(**kwargs)
        self.text = kwargs.get('text', None)
        self.enabled = kwargs.get('enabled', None)
        self.consent_required = kwargs.get('consent_required', None)
