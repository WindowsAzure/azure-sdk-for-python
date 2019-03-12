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


class WebTestPropertiesConfiguration(Model):
    """An XML configuration specification for a WebTest.

    :param web_test: The XML specification of a WebTest to run against an
     application.
    :type web_test: str
    """

    _attribute_map = {
        'web_test': {'key': 'WebTest', 'type': 'str'},
    }

    def __init__(self, web_test=None):
        super(WebTestPropertiesConfiguration, self).__init__()
        self.web_test = web_test
