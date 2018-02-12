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


class CloudPool(Model):
    """A pool in the Azure Batch service.

    :param id: A string that uniquely identifies the pool within the account.
     The ID can contain any combination of alphanumeric characters including
     hyphens and underscores, and cannot contain more than 64 characters. The
     ID is case-preserving and case-insensitive (that is, you may not have two
     IDs within an account that differ only by case).
    :type id: str
    :param display_name: The display name for the pool. The display name need
     not be unique and can contain any Unicode characters up to a maximum
     length of 1024.
    :type display_name: str
    :param url: The URL of the pool.
    :type url: str
    :param e_tag: The ETag of the pool. This is an opaque string. You can use
     it to detect whether the pool has changed between requests. In particular,
     you can be pass the ETag when updating a pool to specify that your changes
     should take effect only if nobody else has modified the pool in the
     meantime.
    :type e_tag: str
    :param last_modified: The last modified time of the pool. This is the last
     time at which the pool level data, such as the targetDedicatedNodes or
     enableAutoscale settings, changed. It does not factor in node-level
     changes such as a compute node changing state.
    :type last_modified: datetime
    :param creation_time: The creation time of the pool.
    :type creation_time: datetime
    :param state: The current state of the pool. Possible values include:
     'active', 'deleting', 'upgrading'
    :type state: str or ~azure.batch.models.PoolState
    :param state_transition_time: The time at which the pool entered its
     current state.
    :type state_transition_time: datetime
    :param allocation_state: Whether the pool is resizing. Possible values
     include: 'steady', 'resizing', 'stopping'
    :type allocation_state: str or ~azure.batch.models.AllocationState
    :param allocation_state_transition_time: The time at which the pool
     entered its current allocation state.
    :type allocation_state_transition_time: datetime
    :param vm_size: The size of virtual machines in the pool. All virtual
     machines in a pool are the same size. For information about available
     sizes of virtual machines for Cloud Services pools (pools created with
     cloudServiceConfiguration), see Sizes for Cloud Services
     (http://azure.microsoft.com/documentation/articles/cloud-services-sizes-specs/).
     Batch supports all Cloud Services VM sizes except ExtraSmall, A1V2 and
     A2V2. For information about available VM sizes for pools using images from
     the Virtual Machines Marketplace (pools created with
     virtualMachineConfiguration) see Sizes for Virtual Machines (Linux)
     (https://azure.microsoft.com/documentation/articles/virtual-machines-linux-sizes/)
     or Sizes for Virtual Machines (Windows)
     (https://azure.microsoft.com/documentation/articles/virtual-machines-windows-sizes/).
     Batch supports all Azure VM sizes except STANDARD_A0 and those with
     premium storage (STANDARD_GS, STANDARD_DS, and STANDARD_DSV2 series).
    :type vm_size: str
    :param cloud_service_configuration: The cloud service configuration for
     the pool. This property and virtualMachineConfiguration are mutually
     exclusive and one of the properties must be specified. This property
     cannot be specified if the Batch account was created with its
     poolAllocationMode property set to 'UserSubscription'.
    :type cloud_service_configuration:
     ~azure.batch.models.CloudServiceConfiguration
    :param virtual_machine_configuration: The virtual machine configuration
     for the pool. This property and cloudServiceConfiguration are mutually
     exclusive and one of the properties must be specified.
    :type virtual_machine_configuration:
     ~azure.batch.models.VirtualMachineConfiguration
    :param resize_timeout: The timeout for allocation of compute nodes to the
     pool. This is the timeout for the most recent resize operation. (The
     initial sizing when the pool is created counts as a resize.) The default
     value is 15 minutes.
    :type resize_timeout: timedelta
    :param resize_errors: A list of errors encountered while performing the
     last resize on the pool. This property is set only if one or more errors
     occurred during the last pool resize, and only when the pool
     allocationState is Steady.
    :type resize_errors: list[~azure.batch.models.ResizeError]
    :param current_dedicated_nodes: The number of dedicated compute nodes
     currently in the pool.
    :type current_dedicated_nodes: int
    :param current_low_priority_nodes: The number of low-priority compute
     nodes currently in the pool. Low-priority compute nodes which have been
     preempted are included in this count.
    :type current_low_priority_nodes: int
    :param target_dedicated_nodes: The desired number of dedicated compute
     nodes in the pool.
    :type target_dedicated_nodes: int
    :param target_low_priority_nodes: The desired number of low-priority
     compute nodes in the pool.
    :type target_low_priority_nodes: int
    :param enable_auto_scale: Whether the pool size should automatically
     adjust over time. If false, at least one of targetDedicateNodes and
     targetLowPriorityNodes must be specified. If true, the autoScaleFormula
     property is required and the pool automatically resizes according to the
     formula. The default value is false.
    :type enable_auto_scale: bool
    :param auto_scale_formula: A formula for the desired number of compute
     nodes in the pool. This property is set only if the pool automatically
     scales, i.e. enableAutoScale is true.
    :type auto_scale_formula: str
    :param auto_scale_evaluation_interval: The time interval at which to
     automatically adjust the pool size according to the autoscale formula.
     This property is set only if the pool automatically scales, i.e.
     enableAutoScale is true.
    :type auto_scale_evaluation_interval: timedelta
    :param auto_scale_run: The results and errors from the last execution of
     the autoscale formula. This property is set only if the pool automatically
     scales, i.e. enableAutoScale is true.
    :type auto_scale_run: ~azure.batch.models.AutoScaleRun
    :param enable_inter_node_communication: Whether the pool permits direct
     communication between nodes. This imposes restrictions on which nodes can
     be assigned to the pool. Specifying this value can reduce the chance of
     the requested number of nodes to be allocated in the pool.
    :type enable_inter_node_communication: bool
    :param network_configuration: The network configuration for the pool.
    :type network_configuration: ~azure.batch.models.NetworkConfiguration
    :param start_task: A task specified to run on each compute node as it
     joins the pool.
    :type start_task: ~azure.batch.models.StartTask
    :param certificate_references: The list of certificates to be installed on
     each compute node in the pool. For Windows compute nodes, the Batch
     service installs the certificates to the specified certificate store and
     location. For Linux compute nodes, the certificates are stored in a
     directory inside the task working directory and an environment variable
     AZ_BATCH_CERTIFICATES_DIR is supplied to the task to query for this
     location. For certificates with visibility of 'remoteUser', a 'certs'
     directory is created in the user's home directory (e.g.,
     /home/{user-name}/certs) and certificates are placed in that directory.
    :type certificate_references:
     list[~azure.batch.models.CertificateReference]
    :param application_package_references: The list of application packages to
     be installed on each compute node in the pool.
    :type application_package_references:
     list[~azure.batch.models.ApplicationPackageReference]
    :param application_licenses: The list of application licenses the Batch
     service will make available on each compute node in the pool. The list of
     application licenses must be a subset of available Batch service
     application licenses. If a license is requested which is not supported,
     pool creation will fail.
    :type application_licenses: list[str]
    :param max_tasks_per_node: The maximum number of tasks that can run
     concurrently on a single compute node in the pool.
    :type max_tasks_per_node: int
    :param task_scheduling_policy: How tasks are distributed across compute
     nodes in a pool.
    :type task_scheduling_policy: ~azure.batch.models.TaskSchedulingPolicy
    :param user_accounts: The list of user accounts to be created on each node
     in the pool.
    :type user_accounts: list[~azure.batch.models.UserAccount]
    :param metadata: A list of name-value pairs associated with the pool as
     metadata.
    :type metadata: list[~azure.batch.models.MetadataItem]
    :param stats: Utilization and resource usage statistics for the entire
     lifetime of the pool.
    :type stats: ~azure.batch.models.PoolStatistics
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
        'e_tag': {'key': 'eTag', 'type': 'str'},
        'last_modified': {'key': 'lastModified', 'type': 'iso-8601'},
        'creation_time': {'key': 'creationTime', 'type': 'iso-8601'},
        'state': {'key': 'state', 'type': 'PoolState'},
        'state_transition_time': {'key': 'stateTransitionTime', 'type': 'iso-8601'},
        'allocation_state': {'key': 'allocationState', 'type': 'AllocationState'},
        'allocation_state_transition_time': {'key': 'allocationStateTransitionTime', 'type': 'iso-8601'},
        'vm_size': {'key': 'vmSize', 'type': 'str'},
        'cloud_service_configuration': {'key': 'cloudServiceConfiguration', 'type': 'CloudServiceConfiguration'},
        'virtual_machine_configuration': {'key': 'virtualMachineConfiguration', 'type': 'VirtualMachineConfiguration'},
        'resize_timeout': {'key': 'resizeTimeout', 'type': 'duration'},
        'resize_errors': {'key': 'resizeErrors', 'type': '[ResizeError]'},
        'current_dedicated_nodes': {'key': 'currentDedicatedNodes', 'type': 'int'},
        'current_low_priority_nodes': {'key': 'currentLowPriorityNodes', 'type': 'int'},
        'target_dedicated_nodes': {'key': 'targetDedicatedNodes', 'type': 'int'},
        'target_low_priority_nodes': {'key': 'targetLowPriorityNodes', 'type': 'int'},
        'enable_auto_scale': {'key': 'enableAutoScale', 'type': 'bool'},
        'auto_scale_formula': {'key': 'autoScaleFormula', 'type': 'str'},
        'auto_scale_evaluation_interval': {'key': 'autoScaleEvaluationInterval', 'type': 'duration'},
        'auto_scale_run': {'key': 'autoScaleRun', 'type': 'AutoScaleRun'},
        'enable_inter_node_communication': {'key': 'enableInterNodeCommunication', 'type': 'bool'},
        'network_configuration': {'key': 'networkConfiguration', 'type': 'NetworkConfiguration'},
        'start_task': {'key': 'startTask', 'type': 'StartTask'},
        'certificate_references': {'key': 'certificateReferences', 'type': '[CertificateReference]'},
        'application_package_references': {'key': 'applicationPackageReferences', 'type': '[ApplicationPackageReference]'},
        'application_licenses': {'key': 'applicationLicenses', 'type': '[str]'},
        'max_tasks_per_node': {'key': 'maxTasksPerNode', 'type': 'int'},
        'task_scheduling_policy': {'key': 'taskSchedulingPolicy', 'type': 'TaskSchedulingPolicy'},
        'user_accounts': {'key': 'userAccounts', 'type': '[UserAccount]'},
        'metadata': {'key': 'metadata', 'type': '[MetadataItem]'},
        'stats': {'key': 'stats', 'type': 'PoolStatistics'},
    }

    def __init__(self, id=None, display_name=None, url=None, e_tag=None, last_modified=None, creation_time=None, state=None, state_transition_time=None, allocation_state=None, allocation_state_transition_time=None, vm_size=None, cloud_service_configuration=None, virtual_machine_configuration=None, resize_timeout=None, resize_errors=None, current_dedicated_nodes=None, current_low_priority_nodes=None, target_dedicated_nodes=None, target_low_priority_nodes=None, enable_auto_scale=None, auto_scale_formula=None, auto_scale_evaluation_interval=None, auto_scale_run=None, enable_inter_node_communication=None, network_configuration=None, start_task=None, certificate_references=None, application_package_references=None, application_licenses=None, max_tasks_per_node=None, task_scheduling_policy=None, user_accounts=None, metadata=None, stats=None):
        super(CloudPool, self).__init__()
        self.id = id
        self.display_name = display_name
        self.url = url
        self.e_tag = e_tag
        self.last_modified = last_modified
        self.creation_time = creation_time
        self.state = state
        self.state_transition_time = state_transition_time
        self.allocation_state = allocation_state
        self.allocation_state_transition_time = allocation_state_transition_time
        self.vm_size = vm_size
        self.cloud_service_configuration = cloud_service_configuration
        self.virtual_machine_configuration = virtual_machine_configuration
        self.resize_timeout = resize_timeout
        self.resize_errors = resize_errors
        self.current_dedicated_nodes = current_dedicated_nodes
        self.current_low_priority_nodes = current_low_priority_nodes
        self.target_dedicated_nodes = target_dedicated_nodes
        self.target_low_priority_nodes = target_low_priority_nodes
        self.enable_auto_scale = enable_auto_scale
        self.auto_scale_formula = auto_scale_formula
        self.auto_scale_evaluation_interval = auto_scale_evaluation_interval
        self.auto_scale_run = auto_scale_run
        self.enable_inter_node_communication = enable_inter_node_communication
        self.network_configuration = network_configuration
        self.start_task = start_task
        self.certificate_references = certificate_references
        self.application_package_references = application_package_references
        self.application_licenses = application_licenses
        self.max_tasks_per_node = max_tasks_per_node
        self.task_scheduling_policy = task_scheduling_policy
        self.user_accounts = user_accounts
        self.metadata = metadata
        self.stats = stats
