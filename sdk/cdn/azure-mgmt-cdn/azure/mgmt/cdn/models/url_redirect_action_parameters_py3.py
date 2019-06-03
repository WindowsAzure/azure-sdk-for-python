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


class UrlRedirectActionParameters(Model):
    """Defines the parameters for the url redirect action.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar odatatype: Required.  Default value:
     "#Microsoft.Azure.Cdn.Models.DeliveryRuleUrlRedirectActionParameters" .
    :vartype odatatype: str
    :param redirect_type: Required. The redirect type the rule will use when
     redirecting traffic. Possible values include: 'Moved', 'Found',
     'TemporaryRedirect', 'PermanentRedirect'
    :type redirect_type: str or ~azure.mgmt.cdn.models.RedirectType
    :param destination_protocol: Protocol to use for the redirect. The default
     value is MatchRequest. Possible values include: 'MatchRequest', 'Http',
     'Https'
    :type destination_protocol: str or
     ~azure.mgmt.cdn.models.DestinationProtocol
    :param custom_path: The full path to redirect. Path cannot be empty and
     must start with /. Leave empty to use the incoming path as destination
     path.
    :type custom_path: str
    :param custom_hostname: Host to redirect. Leave empty to use the incoming
     host as the destination host.
    :type custom_hostname: str
    :param custom_query_string: The set of query strings to be placed in the
     redirect URL. Setting this value would replace any existing query string;
     leave empty to preserve the incoming query string. Query string must be in
     <key>=<value> format. ? and & will be added automatically so do not
     include them.
    :type custom_query_string: str
    :param custom_fragment: Fragment to add to the redirect URL. Fragment is
     the part of the URL that comes after #. Do not include the #.
    :type custom_fragment: str
    """

    _validation = {
        'odatatype': {'required': True, 'constant': True},
        'redirect_type': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'redirect_type': {'key': 'redirectType', 'type': 'str'},
        'destination_protocol': {'key': 'destinationProtocol', 'type': 'str'},
        'custom_path': {'key': 'customPath', 'type': 'str'},
        'custom_hostname': {'key': 'customHostname', 'type': 'str'},
        'custom_query_string': {'key': 'customQueryString', 'type': 'str'},
        'custom_fragment': {'key': 'customFragment', 'type': 'str'},
    }

    odatatype = "#Microsoft.Azure.Cdn.Models.DeliveryRuleUrlRedirectActionParameters"

    def __init__(self, *, redirect_type, destination_protocol=None, custom_path: str=None, custom_hostname: str=None, custom_query_string: str=None, custom_fragment: str=None, **kwargs) -> None:
        super(UrlRedirectActionParameters, self).__init__(**kwargs)
        self.redirect_type = redirect_type
        self.destination_protocol = destination_protocol
        self.custom_path = custom_path
        self.custom_hostname = custom_hostname
        self.custom_query_string = custom_query_string
        self.custom_fragment = custom_fragment
