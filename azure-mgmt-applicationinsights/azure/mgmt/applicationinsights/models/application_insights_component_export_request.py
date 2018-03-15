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


class ApplicationInsightsComponentExportRequest(Model):
    """An Application Insights component Continuous Export configuration request
    definition.

    :param record_types: The document types to be exported, as comma separated
     values. Allowed values include 'Requests', 'Event', 'Exceptions',
     'Metrics', 'PageViews', 'PageViewPerformance', 'Rdd',
     'PerformanceCounters', 'Availability', 'Messages'.
    :type record_types: str
    :param destination_type: The Continuous Export destination type. This has
     to be 'Blob'.
    :type destination_type: str
    :param destination_address: The SAS URL for the destination storage
     container. It must grant write permission.
    :type destination_address: str
    :param is_enabled: Set to 'true' to create a Continuous Export
     configuration as enabled, otherwise set it to 'false'.
    :type is_enabled: str
    :param notification_queue_enabled: Deprecated
    :type notification_queue_enabled: str
    :param notification_queue_uri: Deprecated
    :type notification_queue_uri: str
    :param destination_storage_subscription_id: The subscription ID of the
     destination storage container.
    :type destination_storage_subscription_id: str
    :param destination_storage_location_id: The location ID of the destination
     storage container.
    :type destination_storage_location_id: str
    :param destination_account_id: The name of destination storage account.
    :type destination_account_id: str
    """

    _attribute_map = {
        'record_types': {'key': 'RecordTypes', 'type': 'str'},
        'destination_type': {'key': 'DestinationType', 'type': 'str'},
        'destination_address': {'key': 'DestinationAddress', 'type': 'str'},
        'is_enabled': {'key': 'IsEnabled', 'type': 'str'},
        'notification_queue_enabled': {'key': 'NotificationQueueEnabled', 'type': 'str'},
        'notification_queue_uri': {'key': 'NotificationQueueUri', 'type': 'str'},
        'destination_storage_subscription_id': {'key': 'DestinationStorageSubscriptionId', 'type': 'str'},
        'destination_storage_location_id': {'key': 'DestinationStorageLocationId', 'type': 'str'},
        'destination_account_id': {'key': 'DestinationAccountId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ApplicationInsightsComponentExportRequest, self).__init__(**kwargs)
        self.record_types = kwargs.get('record_types', None)
        self.destination_type = kwargs.get('destination_type', None)
        self.destination_address = kwargs.get('destination_address', None)
        self.is_enabled = kwargs.get('is_enabled', None)
        self.notification_queue_enabled = kwargs.get('notification_queue_enabled', None)
        self.notification_queue_uri = kwargs.get('notification_queue_uri', None)
        self.destination_storage_subscription_id = kwargs.get('destination_storage_subscription_id', None)
        self.destination_storage_location_id = kwargs.get('destination_storage_location_id', None)
        self.destination_account_id = kwargs.get('destination_account_id', None)
