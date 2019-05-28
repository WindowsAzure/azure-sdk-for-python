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


class PolicySettings(Model):
    """Defines top-level WebApplicationFirewallPolicy configuration settings.

    :param enabled_state: Describes if the policy is in enabled or disabled
     state. Defaults to Enabled if not specified. Possible values include:
     'Disabled', 'Enabled'
    :type enabled_state: str or
     ~azure.mgmt.frontdoor.models.PolicyEnabledState
    :param mode: Describes if it is in detection mode or prevention mode at
     policy level. Possible values include: 'Prevention', 'Detection'
    :type mode: str or ~azure.mgmt.frontdoor.models.PolicyMode
    :param redirect_url: If action type is redirect, this field represents
     redirect URL for the client.
    :type redirect_url: str
    :param custom_block_response_status_code: If the action type is block,
     customer can override the response status code.
    :type custom_block_response_status_code: int
    :param custom_block_response_body: If the action type is block, customer
     can override the response body. The body must be specified in base64
     encoding.
    :type custom_block_response_body: str
    """

    _validation = {
        'custom_block_response_body': {'pattern': r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$'},
    }

    _attribute_map = {
        'enabled_state': {'key': 'enabledState', 'type': 'str'},
        'mode': {'key': 'mode', 'type': 'str'},
        'redirect_url': {'key': 'redirectUrl', 'type': 'str'},
        'custom_block_response_status_code': {'key': 'customBlockResponseStatusCode', 'type': 'int'},
        'custom_block_response_body': {'key': 'customBlockResponseBody', 'type': 'str'},
    }

    def __init__(self, *, enabled_state=None, mode=None, redirect_url: str=None, custom_block_response_status_code: int=None, custom_block_response_body: str=None, **kwargs) -> None:
        super(PolicySettings, self).__init__(**kwargs)
        self.enabled_state = enabled_state
        self.mode = mode
        self.redirect_url = redirect_url
        self.custom_block_response_status_code = custom_block_response_status_code
        self.custom_block_response_body = custom_block_response_body
