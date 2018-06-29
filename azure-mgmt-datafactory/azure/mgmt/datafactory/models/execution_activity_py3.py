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

from .activity import Activity


class ExecutionActivity(Activity):
    """Base class for all execution activities.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: DatabricksNotebookActivity, DataLakeAnalyticsUSQLActivity,
    AzureMLUpdateResourceActivity, AzureMLBatchExecutionActivity,
    GetMetadataActivity, WebActivity, LookupActivity,
    SqlServerStoredProcedureActivity, CustomActivity,
    ExecuteSSISPackageActivity, HDInsightSparkActivity,
    HDInsightStreamingActivity, HDInsightMapReduceActivity,
    HDInsightPigActivity, HDInsightHiveActivity, CopyActivity

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param name: Required. Activity name.
    :type name: str
    :param description: Activity description.
    :type description: str
    :param depends_on: Activity depends on condition.
    :type depends_on: list[~azure.mgmt.datafactory.models.ActivityDependency]
    :param type: Required. Constant filled by server.
    :type type: str
    :param linked_service_name: Linked service reference.
    :type linked_service_name:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param policy: Activity policy.
    :type policy: ~azure.mgmt.datafactory.models.ActivityPolicy
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'depends_on': {'key': 'dependsOn', 'type': '[ActivityDependency]'},
        'type': {'key': 'type', 'type': 'str'},
        'linked_service_name': {'key': 'linkedServiceName', 'type': 'LinkedServiceReference'},
        'policy': {'key': 'policy', 'type': 'ActivityPolicy'},
    }

    _subtype_map = {
        'type': {'DatabricksNotebook': 'DatabricksNotebookActivity', 'DataLakeAnalyticsU-SQL': 'DataLakeAnalyticsUSQLActivity', 'AzureMLUpdateResource': 'AzureMLUpdateResourceActivity', 'AzureMLBatchExecution': 'AzureMLBatchExecutionActivity', 'GetMetadata': 'GetMetadataActivity', 'WebActivity': 'WebActivity', 'Lookup': 'LookupActivity', 'SqlServerStoredProcedure': 'SqlServerStoredProcedureActivity', 'Custom': 'CustomActivity', 'ExecuteSSISPackage': 'ExecuteSSISPackageActivity', 'HDInsightSpark': 'HDInsightSparkActivity', 'HDInsightStreaming': 'HDInsightStreamingActivity', 'HDInsightMapReduce': 'HDInsightMapReduceActivity', 'HDInsightPig': 'HDInsightPigActivity', 'HDInsightHive': 'HDInsightHiveActivity', 'Copy': 'CopyActivity'}
    }

    def __init__(self, *, name: str, additional_properties=None, description: str=None, depends_on=None, linked_service_name=None, policy=None, **kwargs) -> None:
        super(ExecutionActivity, self).__init__(additional_properties=additional_properties, name=name, description=description, depends_on=depends_on, **kwargs)
        self.linked_service_name = linked_service_name
        self.policy = policy
        self.type = 'Execution'
