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

from .execution_activity_py3 import ExecutionActivity


class CopyActivity(ExecutionActivity):
    """Copy activity.

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
    :param source: Required. Copy activity source.
    :type source: ~azure.mgmt.datafactory.models.CopySource
    :param sink: Required. Copy activity sink.
    :type sink: ~azure.mgmt.datafactory.models.CopySink
    :param translator: Copy activity translator. If not specified, tabular
     translator is used.
    :type translator: ~azure.mgmt.datafactory.models.CopyTranslator
    :param enable_staging: Specifies whether to copy data via an interim
     staging. Default value is false. Type: boolean (or Expression with
     resultType boolean).
    :type enable_staging: object
    :param staging_settings: Specifies interim staging settings when
     EnableStaging is true.
    :type staging_settings: ~azure.mgmt.datafactory.models.StagingSettings
    :param parallel_copies: Maximum number of concurrent sessions opened on
     the source or sink to avoid overloading the data store. Type: integer (or
     Expression with resultType integer), minimum: 0.
    :type parallel_copies: object
    :param data_integration_units: Maximum number of data integration units
     that can be used to perform this data movement. Type: integer (or
     Expression with resultType integer), minimum: 0.
    :type data_integration_units: object
    :param enable_skip_incompatible_row: Whether to skip incompatible row.
     Default value is false. Type: boolean (or Expression with resultType
     boolean).
    :type enable_skip_incompatible_row: object
    :param redirect_incompatible_row_settings: Redirect incompatible row
     settings when EnableSkipIncompatibleRow is true.
    :type redirect_incompatible_row_settings:
     ~azure.mgmt.datafactory.models.RedirectIncompatibleRowSettings
    :param preserve_rules: Preserve Rules.
    :type preserve_rules: list[object]
    :param inputs: List of inputs for the activity.
    :type inputs: list[~azure.mgmt.datafactory.models.DatasetReference]
    :param outputs: List of outputs for the activity.
    :type outputs: list[~azure.mgmt.datafactory.models.DatasetReference]
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
        'source': {'required': True},
        'sink': {'required': True},
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
        'source': {'key': 'typeProperties.source', 'type': 'CopySource'},
        'sink': {'key': 'typeProperties.sink', 'type': 'CopySink'},
        'translator': {'key': 'typeProperties.translator', 'type': 'CopyTranslator'},
        'enable_staging': {'key': 'typeProperties.enableStaging', 'type': 'object'},
        'staging_settings': {'key': 'typeProperties.stagingSettings', 'type': 'StagingSettings'},
        'parallel_copies': {'key': 'typeProperties.parallelCopies', 'type': 'object'},
        'data_integration_units': {'key': 'typeProperties.dataIntegrationUnits', 'type': 'object'},
        'enable_skip_incompatible_row': {'key': 'typeProperties.enableSkipIncompatibleRow', 'type': 'object'},
        'redirect_incompatible_row_settings': {'key': 'typeProperties.redirectIncompatibleRowSettings', 'type': 'RedirectIncompatibleRowSettings'},
        'preserve_rules': {'key': 'typeProperties.preserveRules', 'type': '[object]'},
        'inputs': {'key': 'inputs', 'type': '[DatasetReference]'},
        'outputs': {'key': 'outputs', 'type': '[DatasetReference]'},
    }

    def __init__(self, *, name: str, source, sink, additional_properties=None, description: str=None, depends_on=None, user_properties=None, linked_service_name=None, policy=None, translator=None, enable_staging=None, staging_settings=None, parallel_copies=None, data_integration_units=None, enable_skip_incompatible_row=None, redirect_incompatible_row_settings=None, preserve_rules=None, inputs=None, outputs=None, **kwargs) -> None:
        super(CopyActivity, self).__init__(additional_properties=additional_properties, name=name, description=description, depends_on=depends_on, user_properties=user_properties, linked_service_name=linked_service_name, policy=policy, **kwargs)
        self.source = source
        self.sink = sink
        self.translator = translator
        self.enable_staging = enable_staging
        self.staging_settings = staging_settings
        self.parallel_copies = parallel_copies
        self.data_integration_units = data_integration_units
        self.enable_skip_incompatible_row = enable_skip_incompatible_row
        self.redirect_incompatible_row_settings = redirect_incompatible_row_settings
        self.preserve_rules = preserve_rules
        self.inputs = inputs
        self.outputs = outputs
        self.type = 'Copy'
