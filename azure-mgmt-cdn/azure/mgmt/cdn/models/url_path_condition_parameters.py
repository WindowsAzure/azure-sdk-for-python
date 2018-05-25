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


class UrlPathConditionParameters(Model):
    """Defines the parameters for the URL path condition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar odatatype: Required.  Default value:
     "Microsoft.Azure.Cdn.Models.DeliveryRuleUrlPathConditionParameters" .
    :vartype odatatype: str
    :param path: Required. A URL path for the condition of the delivery rule
    :type path: str
    :param match_type: Required. The match type for the condition of the
     delivery rule. Possible values include: 'Literal', 'Wildcard'
    :type match_type: str or ~azure.mgmt.cdn.models.enum
    """

    _validation = {
        'odatatype': {'required': True, 'constant': True},
        'path': {'required': True},
        'match_type': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'path': {'key': 'path', 'type': 'str'},
        'match_type': {'key': 'matchType', 'type': 'str'},
    }

    odatatype = "Microsoft.Azure.Cdn.Models.DeliveryRuleUrlPathConditionParameters"

    def __init__(self, **kwargs):
        super(UrlPathConditionParameters, self).__init__(**kwargs)
        self.path = kwargs.get('path', None)
        self.match_type = kwargs.get('match_type', None)
