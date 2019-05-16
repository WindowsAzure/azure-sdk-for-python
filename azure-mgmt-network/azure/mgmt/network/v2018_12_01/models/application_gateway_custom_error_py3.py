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


class ApplicationGatewayCustomError(Model):
    """Customer error of an application gateway.

    :param status_code: Status code of the application gateway customer error.
     Possible values include: 'HttpStatus403', 'HttpStatus502'
    :type status_code: str or
     ~azure.mgmt.network.v2018_12_01.models.ApplicationGatewayCustomErrorStatusCode
    :param custom_error_page_url: Error page URL of the application gateway
     customer error.
    :type custom_error_page_url: str
    """

    _attribute_map = {
        'status_code': {'key': 'statusCode', 'type': 'str'},
        'custom_error_page_url': {'key': 'customErrorPageUrl', 'type': 'str'},
    }

    def __init__(self, *, status_code=None, custom_error_page_url: str=None, **kwargs) -> None:
        super(ApplicationGatewayCustomError, self).__init__(**kwargs)
        self.status_code = status_code
        self.custom_error_page_url = custom_error_page_url
