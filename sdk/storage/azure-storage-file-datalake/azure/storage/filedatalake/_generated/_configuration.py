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

from azure.core.configuration import Configuration
from azure.core.pipeline import policies

from .version import VERSION


class DataLakeStorageClientConfiguration(Configuration):
    """Configuration for DataLakeStorageClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param url: The URL of the service account, container, or blob that is the
     targe of the desired operation.
    :type url: str
    :param file_system: The filesystem identifier.
    :type file_system: str
    :param path1: The file or directory path.
    :type path1: str
    :ivar resource: The value must be "filesystem" for all filesystem
     operations.
    :type resource: str
    :ivar version: Specifies the version of the operation to use for this
     request.
    :type version: str
    """

    def __init__(self, url, file_system, path1, **kwargs):

        if url is None:
            raise ValueError("Parameter 'url' must not be None.")

        super(DataLakeStorageClientConfiguration, self).__init__(**kwargs)
        self._configure(**kwargs)

        self.user_agent_policy.add_user_agent('azsdk-python-datalakestorageclient/{}'.format(VERSION))
        self.generate_client_request_id = True

        self.url = url
        self.file_system = file_system
        self.path1 = path1
        self.resource = "filesystem"
        self.version = "2020-02-10"

    def _configure(self, **kwargs):
        self.user_agent_policy = kwargs.get('user_agent_policy') or policies.UserAgentPolicy(**kwargs)
        self.headers_policy = kwargs.get('headers_policy') or policies.HeadersPolicy(**kwargs)
        self.proxy_policy = kwargs.get('proxy_policy') or policies.ProxyPolicy(**kwargs)
        self.logging_policy = kwargs.get('logging_policy') or policies.NetworkTraceLoggingPolicy(**kwargs)
        self.retry_policy = kwargs.get('retry_policy') or policies.RetryPolicy(**kwargs)
        self.custom_hook_policy = kwargs.get('custom_hook_policy') or policies.CustomHookPolicy(**kwargs)
        self.redirect_policy = kwargs.get('redirect_policy') or policies.RedirectPolicy(**kwargs)
