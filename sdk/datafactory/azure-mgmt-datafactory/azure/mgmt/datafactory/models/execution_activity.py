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
    sub-classes are: AzureFunctionActivity, DatabricksSparkPythonActivity,
    DatabricksSparkJarActivity, DatabricksNotebookActivity,
    DataLakeAnalyticsUSQLActivity, AzureMLUpdateResourceActivity,
    AzureMLBatchExecutionActivity, GetMetadataActivity, WebActivity,
    LookupActivity, AzureDataExplorerCommandActivity, DeleteActivity,
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
    :param user_properties: Activity user properties.
    :type user_properties: list[~azure.mgmt.datafactory.models.UserProperty]
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
        'user_properties': {'key': 'userProperties', 'type': '[UserProperty]'},
        'type': {'key': 'type', 'type': 'str'},
        'linked_service_name': {'key': 'linkedServiceName', 'type': 'LinkedServiceReference'},
        'policy': {'key': 'policy', 'type': 'ActivityPolicy'},
    }

    _subtype_map = {
        'type': {'AzureFunctionActivity': 'AzureFunctionActivity', 'DatabricksSparkPython': 'DatabricksSparkPythonActivity', 'DatabricksSparkJar': 'DatabricksSparkJarActivity', 'DatabricksNotebook': 'DatabricksNotebookActivity', 'DataLakeAnalyticsU-SQL': 'DataLakeAnalyticsUSQLActivity', 'AzureMLUpdateResource': 'AzureMLUpdateResourceActivity', 'AzureMLBatchExecution': 'AzureMLBatchExecutionActivity', 'GetMetadata': 'GetMetadataActivity', 'WebActivity': 'WebActivity', 'Lookup': 'LookupActivity', 'AzureDataExplorerCommand': 'AzureDataExplorerCommandActivity', 'Delete': 'DeleteActivity', 'SqlServerStoredProcedure': 'SqlServerStoredProcedureActivity', 'Custom': 'CustomActivity', 'ExecuteSSISPackage': 'ExecuteSSISPackageActivity', 'HDInsightSpark': 'HDInsightSparkActivity', 'HDInsightStreaming': 'HDInsightStreamingActivity', 'HDInsightMapReduce': 'HDInsightMapReduceActivity', 'HDInsightPig': 'HDInsightPigActivity', 'HDInsightHive': 'HDInsightHiveActivity', 'Copy': 'CopyActivity'}
    }

    def __init__(self, **kwargs):
        super(ExecutionActivity, self).__init__(**kwargs)
        self.linked_service_name = kwargs.get('linked_service_name', None)
        self.policy = kwargs.get('policy', None)
        self.type = 'Execution'
