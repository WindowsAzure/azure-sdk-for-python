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


class TaskAddParameter(Model):
    """An Azure Batch task to add.

    :param id: A string that uniquely identifies the task within the job. The
     ID can contain any combination of alphanumeric characters including
     hyphens and underscores, and cannot contain more than 64 characters. The
     ID is case-preserving and case-insensitive (that is, you may not have two
     IDs within a job that differ only by case).
    :type id: str
    :param display_name: A display name for the task. The display name need
     not be unique and can contain any Unicode characters up to a maximum
     length of 1024.
    :type display_name: str
    :param command_line: The command line of the task. For multi-instance
     tasks, the command line is executed as the primary task, after the primary
     task and all subtasks have finished executing the coordination command
     line. The command line does not run under a shell, and therefore cannot
     take advantage of shell features such as environment variable expansion.
     If you want to take advantage of such features, you should invoke the
     shell in the command line, for example using "cmd /c MyCommand" in Windows
     or "/bin/sh -c MyCommand" in Linux.
    :type command_line: str
    :param exit_conditions: How the Batch service should respond when the task
     completes.
    :type exit_conditions: :class:`ExitConditions
     <azure.batch.models.ExitConditions>`
    :param resource_files: A list of files that the Batch service will
     download to the compute node before running the command line. For
     multi-instance tasks, the resource files will only be downloaded to the
     compute node on which the primary task is executed.
    :type resource_files: list of :class:`ResourceFile
     <azure.batch.models.ResourceFile>`
    :param environment_settings: A list of environment variable settings for
     the task.
    :type environment_settings: list of :class:`EnvironmentSetting
     <azure.batch.models.EnvironmentSetting>`
    :param affinity_info: A locality hint that can be used by the Batch
     service to select a compute node on which to start the new task.
    :type affinity_info: :class:`AffinityInformation
     <azure.batch.models.AffinityInformation>`
    :param constraints: The execution constraints that apply to this task. If
     you do not specify constraints, the maxTaskRetryCount is the
     maxTaskRetryCount specified for the job, and the maxWallClockTime and
     retentionTime are infinite.
    :type constraints: :class:`TaskConstraints
     <azure.batch.models.TaskConstraints>`
    :param run_elevated: Whether to run the task in elevated mode. The default
     value is false.
    :type run_elevated: bool
    :param multi_instance_settings: An object that indicates that the task is
     a multi-instance task, and contains information about how to run the
     multi-instance task.
    :type multi_instance_settings: :class:`MultiInstanceSettings
     <azure.batch.models.MultiInstanceSettings>`
    :param depends_on: The tasks that this task depends on. The task will not
     be scheduled until all depended-on tasks have completed successfully. (If
     any depended-on tasks fail and exhaust their retry counts, the task will
     never be scheduled.) If the job does not have usesTaskDependencies set to
     true, and this element is present, the request fails with error code
     TaskDependenciesNotSpecifiedOnJob.
    :type depends_on: :class:`TaskDependencies
     <azure.batch.models.TaskDependencies>`
    :param application_package_references: A list of application packages that
     the Batch service will deploy to the compute node before running the
     command line.
    :type application_package_references: list of
     :class:`ApplicationPackageReference
     <azure.batch.models.ApplicationPackageReference>`
    """

    _validation = {
        'id': {'required': True},
        'command_line': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'command_line': {'key': 'commandLine', 'type': 'str'},
        'exit_conditions': {'key': 'exitConditions', 'type': 'ExitConditions'},
        'resource_files': {'key': 'resourceFiles', 'type': '[ResourceFile]'},
        'environment_settings': {'key': 'environmentSettings', 'type': '[EnvironmentSetting]'},
        'affinity_info': {'key': 'affinityInfo', 'type': 'AffinityInformation'},
        'constraints': {'key': 'constraints', 'type': 'TaskConstraints'},
        'run_elevated': {'key': 'runElevated', 'type': 'bool'},
        'multi_instance_settings': {'key': 'multiInstanceSettings', 'type': 'MultiInstanceSettings'},
        'depends_on': {'key': 'dependsOn', 'type': 'TaskDependencies'},
        'application_package_references': {'key': 'applicationPackageReferences', 'type': '[ApplicationPackageReference]'},
    }

    def __init__(self, id, command_line, display_name=None, exit_conditions=None, resource_files=None, environment_settings=None, affinity_info=None, constraints=None, run_elevated=None, multi_instance_settings=None, depends_on=None, application_package_references=None):
        self.id = id
        self.display_name = display_name
        self.command_line = command_line
        self.exit_conditions = exit_conditions
        self.resource_files = resource_files
        self.environment_settings = environment_settings
        self.affinity_info = affinity_info
        self.constraints = constraints
        self.run_elevated = run_elevated
        self.multi_instance_settings = multi_instance_settings
        self.depends_on = depends_on
        self.application_package_references = application_package_references
