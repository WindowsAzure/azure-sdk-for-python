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


class ApplicationInsightsComponentQuotaStatus(Model):
    """An Application Insights component daily data volume cap status.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar app_id: The Application ID for the Application Insights component.
    :vartype app_id: str
    :ivar should_be_throttled: The daily data volume cap is met, and data
     ingestion will be stopped.
    :vartype should_be_throttled: bool
    :ivar expiration_time: Date and time when the daily data volume cap will
     be reset, and data ingestion will resume.
    :vartype expiration_time: str
    """

    _validation = {
        'app_id': {'readonly': True},
        'should_be_throttled': {'readonly': True},
        'expiration_time': {'readonly': True},
    }

    _attribute_map = {
        'app_id': {'key': 'AppId', 'type': 'str'},
        'should_be_throttled': {'key': 'ShouldBeThrottled', 'type': 'bool'},
        'expiration_time': {'key': 'ExpirationTime', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(ApplicationInsightsComponentQuotaStatus, self).__init__(**kwargs)
        self.app_id = None
        self.should_be_throttled = None
        self.expiration_time = None
