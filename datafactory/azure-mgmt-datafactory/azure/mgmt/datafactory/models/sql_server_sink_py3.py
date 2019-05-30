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

from .copy_sink_py3 import CopySink


class SqlServerSink(CopySink):
    """A copy activity SQL server sink.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param write_batch_size: Write batch size. Type: integer (or Expression
     with resultType integer), minimum: 0.
    :type write_batch_size: object
    :param write_batch_timeout: Write batch timeout. Type: string (or
     Expression with resultType string), pattern:
     ((\\d+)\\.)?(\\d\\d):(60|([0-5][0-9])):(60|([0-5][0-9])).
    :type write_batch_timeout: object
    :param sink_retry_count: Sink retry count. Type: integer (or Expression
     with resultType integer).
    :type sink_retry_count: object
    :param sink_retry_wait: Sink retry wait. Type: string (or Expression with
     resultType string), pattern:
     ((\\d+)\\.)?(\\d\\d):(60|([0-5][0-9])):(60|([0-5][0-9])).
    :type sink_retry_wait: object
    :param max_concurrent_connections: The maximum concurrent connection count
     for the sink data store. Type: integer (or Expression with resultType
     integer).
    :type max_concurrent_connections: object
    :param type: Required. Constant filled by server.
    :type type: str
    :param sql_writer_stored_procedure_name: SQL writer stored procedure name.
     Type: string (or Expression with resultType string).
    :type sql_writer_stored_procedure_name: object
    :param sql_writer_table_type: SQL writer table type. Type: string (or
     Expression with resultType string).
    :type sql_writer_table_type: object
    :param pre_copy_script: SQL pre-copy script. Type: string (or Expression
     with resultType string).
    :type pre_copy_script: object
    :param stored_procedure_parameters: SQL stored procedure parameters.
    :type stored_procedure_parameters: dict[str,
     ~azure.mgmt.datafactory.models.StoredProcedureParameter]
    :param stored_procedure_table_type_parameter_name: The stored procedure
     parameter name of the table type. Type: string (or Expression with
     resultType string).
    :type stored_procedure_table_type_parameter_name: object
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'write_batch_size': {'key': 'writeBatchSize', 'type': 'object'},
        'write_batch_timeout': {'key': 'writeBatchTimeout', 'type': 'object'},
        'sink_retry_count': {'key': 'sinkRetryCount', 'type': 'object'},
        'sink_retry_wait': {'key': 'sinkRetryWait', 'type': 'object'},
        'max_concurrent_connections': {'key': 'maxConcurrentConnections', 'type': 'object'},
        'type': {'key': 'type', 'type': 'str'},
        'sql_writer_stored_procedure_name': {'key': 'sqlWriterStoredProcedureName', 'type': 'object'},
        'sql_writer_table_type': {'key': 'sqlWriterTableType', 'type': 'object'},
        'pre_copy_script': {'key': 'preCopyScript', 'type': 'object'},
        'stored_procedure_parameters': {'key': 'storedProcedureParameters', 'type': '{StoredProcedureParameter}'},
        'stored_procedure_table_type_parameter_name': {'key': 'storedProcedureTableTypeParameterName', 'type': 'object'},
    }

    def __init__(self, *, additional_properties=None, write_batch_size=None, write_batch_timeout=None, sink_retry_count=None, sink_retry_wait=None, max_concurrent_connections=None, sql_writer_stored_procedure_name=None, sql_writer_table_type=None, pre_copy_script=None, stored_procedure_parameters=None, stored_procedure_table_type_parameter_name=None, **kwargs) -> None:
        super(SqlServerSink, self).__init__(additional_properties=additional_properties, write_batch_size=write_batch_size, write_batch_timeout=write_batch_timeout, sink_retry_count=sink_retry_count, sink_retry_wait=sink_retry_wait, max_concurrent_connections=max_concurrent_connections, **kwargs)
        self.sql_writer_stored_procedure_name = sql_writer_stored_procedure_name
        self.sql_writer_table_type = sql_writer_table_type
        self.pre_copy_script = pre_copy_script
        self.stored_procedure_parameters = stored_procedure_parameters
        self.stored_procedure_table_type_parameter_name = stored_procedure_table_type_parameter_name
        self.type = 'SqlServerSink'
