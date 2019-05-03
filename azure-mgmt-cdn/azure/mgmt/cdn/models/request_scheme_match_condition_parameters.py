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


class RequestSchemeMatchConditionParameters(Model):
    """Defines the parameters for RequestScheme match conditions .

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar odatatype: Required.  Default value:
     "Microsoft.Azure.Cdn.Models.DeliveryRuleRequestSchemeConditionParameters"
     .
    :vartype odatatype: str
    :ivar operator: Required. Describes operator to be matched. Default value:
     "Equal" .
    :vartype operator: str
    :param negate_condition: Describes if this is negate condition or not
    :type negate_condition: bool
    :param match_values: Required. The match value for the condition of the
     delivery rule
    :type match_values: list[str]
    """

    _validation = {
        'odatatype': {'required': True, 'constant': True},
        'operator': {'required': True, 'constant': True},
        'match_values': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'operator': {'key': 'operator', 'type': 'str'},
        'negate_condition': {'key': 'negateCondition', 'type': 'bool'},
        'match_values': {'key': 'matchValues', 'type': '[str]'},
    }

    odatatype = "Microsoft.Azure.Cdn.Models.DeliveryRuleRequestSchemeConditionParameters"

    operator = "Equal"

    def __init__(self, **kwargs):
        super(RequestSchemeMatchConditionParameters, self).__init__(**kwargs)
        self.negate_condition = kwargs.get('negate_condition', None)
        self.match_values = kwargs.get('match_values', None)
