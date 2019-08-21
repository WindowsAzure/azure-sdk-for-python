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

from .data_connection_py3 import DataConnection


class IotHubDataConnection(DataConnection):
    """Class representing an iot hub data connection.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param iot_hub_resource_id: Required. The resource ID of the Iot hub to be
     used to create a data connection.
    :type iot_hub_resource_id: str
    :param consumer_group: Required. The iot hub consumer group.
    :type consumer_group: str
    :param table_name: The table where the data should be ingested. Optionally
     the table information can be added to each message.
    :type table_name: str
    :param mapping_rule_name: The mapping rule to be used to ingest the data.
     Optionally the mapping information can be added to each message.
    :type mapping_rule_name: str
    :param data_format: The data format of the message. Optionally the data
     format can be added to each message. Possible values include: 'MULTIJSON',
     'JSON', 'CSV', 'TSV', 'SCSV', 'SOHSV', 'PSV', 'TXT', 'RAW', 'SINGLEJSON',
     'AVRO'
    :type data_format: str or ~azure.mgmt.kusto.models.DataFormat
    :param event_system_properties: System properties of the iot hub
    :type event_system_properties: list[str]
    :param shared_access_policy_name: Required. The name of the share access
     policy name
    :type shared_access_policy_name: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'kind': {'required': True},
        'iot_hub_resource_id': {'required': True},
        'consumer_group': {'required': True},
        'shared_access_policy_name': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'iot_hub_resource_id': {'key': 'properties.iotHubResourceId', 'type': 'str'},
        'consumer_group': {'key': 'properties.consumerGroup', 'type': 'str'},
        'table_name': {'key': 'properties.tableName', 'type': 'str'},
        'mapping_rule_name': {'key': 'properties.mappingRuleName', 'type': 'str'},
        'data_format': {'key': 'properties.dataFormat', 'type': 'str'},
        'event_system_properties': {'key': 'properties.eventSystemProperties', 'type': '[str]'},
        'shared_access_policy_name': {'key': 'properties.sharedAccessPolicyName', 'type': 'str'},
    }

    def __init__(self, *, iot_hub_resource_id: str, consumer_group: str, shared_access_policy_name: str, location: str=None, table_name: str=None, mapping_rule_name: str=None, data_format=None, event_system_properties=None, **kwargs) -> None:
        super(IotHubDataConnection, self).__init__(location=location, **kwargs)
        self.iot_hub_resource_id = iot_hub_resource_id
        self.consumer_group = consumer_group
        self.table_name = table_name
        self.mapping_rule_name = mapping_rule_name
        self.data_format = data_format
        self.event_system_properties = event_system_properties
        self.shared_access_policy_name = shared_access_policy_name
        self.kind = 'IotHub'
