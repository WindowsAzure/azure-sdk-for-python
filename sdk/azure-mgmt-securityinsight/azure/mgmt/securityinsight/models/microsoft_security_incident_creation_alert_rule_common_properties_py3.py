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


class MicrosoftSecurityIncidentCreationAlertRuleCommonProperties(Model):
    """MicrosoftSecurityIncidentCreation rule common property bag.

    All required parameters must be populated in order to send to Azure.

    :param display_names_filter: the alerts' displayNames on which the cases
     will be generated
    :type display_names_filter: list[str]
    :param product_filter: Required. The alerts' productName on which the
     cases will be generated. Possible values include: 'Microsoft Cloud App
     Security', 'Azure Security Center', 'Azure Advanced Threat Protection',
     'Azure Active Directory Identity Protection', 'Azure Security Center for
     IoT'
    :type product_filter: str or
     ~azure.mgmt.securityinsight.models.MicrosoftSecurityProductName
    :param severities_filter: the alerts' severities on which the cases will
     be generated
    :type severities_filter: list[str or
     ~azure.mgmt.securityinsight.models.AlertSeverity]
    """

    _validation = {
        'product_filter': {'required': True},
    }

    _attribute_map = {
        'display_names_filter': {'key': 'displayNamesFilter', 'type': '[str]'},
        'product_filter': {'key': 'productFilter', 'type': 'str'},
        'severities_filter': {'key': 'severitiesFilter', 'type': '[str]'},
    }

    def __init__(self, *, product_filter, display_names_filter=None, severities_filter=None, **kwargs) -> None:
        super(MicrosoftSecurityIncidentCreationAlertRuleCommonProperties, self).__init__(**kwargs)
        self.display_names_filter = display_names_filter
        self.product_filter = product_filter
        self.severities_filter = severities_filter
