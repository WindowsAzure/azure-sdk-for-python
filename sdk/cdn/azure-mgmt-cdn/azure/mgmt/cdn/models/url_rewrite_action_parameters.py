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


class UrlRewriteActionParameters(Model):
    """Defines the parameters for the url rewrite action.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar odatatype: Required.  Default value:
     "#Microsoft.Azure.Cdn.Models.DeliveryRuleUrlRewriteActionParameters" .
    :vartype odatatype: str
    :param source_pattern: Required. define a request URI pattern that
     identifies the type of requests that may be rewritten. If value is blank,
     all strings are matched.
    :type source_pattern: str
    :param destination: Required. Define the relative URL to which the above
     requests will be rewritten by.
    :type destination: str
    :param preserve_unmatched_path: Whether to preserve unmatched path.
     Default value is true.
    :type preserve_unmatched_path: bool
    """

    _validation = {
        'odatatype': {'required': True, 'constant': True},
        'source_pattern': {'required': True},
        'destination': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'source_pattern': {'key': 'sourcePattern', 'type': 'str'},
        'destination': {'key': 'destination', 'type': 'str'},
        'preserve_unmatched_path': {'key': 'preserveUnmatchedPath', 'type': 'bool'},
    }

    odatatype = "#Microsoft.Azure.Cdn.Models.DeliveryRuleUrlRewriteActionParameters"

    def __init__(self, **kwargs):
        super(UrlRewriteActionParameters, self).__init__(**kwargs)
        self.source_pattern = kwargs.get('source_pattern', None)
        self.destination = kwargs.get('destination', None)
        self.preserve_unmatched_path = kwargs.get('preserve_unmatched_path', None)
