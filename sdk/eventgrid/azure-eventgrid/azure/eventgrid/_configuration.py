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


class EventGridClientConfiguration(Configuration):
    """Configuration for EventGridClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Subscription credentials which uniquely identify
     client subscription.
    :type credentials: None
    """

    def __init__(
            self, credentials):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        base_url = 'https://{topicHostname}'

        super(EventGridClientConfiguration, self).__init__(base_url)

        # Starting Autorest.Python 4.0.64, make connection pool activated by default
        self.keep_alive = True

        self.add_user_agent('azure-eventgrid/{}'.format(VERSION))

        self.credentials = credentials
