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


class TopLevelDomainAgreementOption(Model):
    """Options for retrieving the list of top level domain legal agreements.

    :param include_privacy: If <code>true</code>, then the list of agreements
     will include agreements for domain privacy as well; otherwise,
     <code>false</code>.
    :type include_privacy: bool
    :param for_transfer: If <code>true</code>, then the list of agreements
     will include agreements for domain transfer as well; otherwise,
     <code>false</code>.
    :type for_transfer: bool
    """

    _attribute_map = {
        'include_privacy': {'key': 'includePrivacy', 'type': 'bool'},
        'for_transfer': {'key': 'forTransfer', 'type': 'bool'},
    }

    def __init__(self, include_privacy=None, for_transfer=None):
        super(TopLevelDomainAgreementOption, self).__init__()
        self.include_privacy = include_privacy
        self.for_transfer = for_transfer
