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

from msrest import Configuration

from .version import VERSION


class AzureContainerRegistryConfiguration(Configuration):
    """Configuration for AzureContainerRegistry
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param login_uri: Registry login URL
    :type login_uri: str
    """

    def __init__(
            self, login_uri):

        if login_uri is None:
            raise ValueError("Parameter 'login_uri' must not be None.")
        base_url = '{url}'

        super(AzureContainerRegistryConfiguration, self).__init__(base_url)

        # Starting Autorest.Python 4.0.64, make connection pool activated by default
        self.keep_alive = True

        self.add_user_agent('azure-containerregistry/{}'.format(VERSION))

        self.login_uri = login_uri
