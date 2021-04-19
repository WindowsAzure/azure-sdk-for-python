# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum, EnumMeta
from six import with_metaclass

class _CaseInsensitiveEnumMeta(EnumMeta):
    def __getitem__(self, name):
        return super().__getitem__(name.upper())

    def __getattr__(cls, name):
        """Return the enum member matching `name`
        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.
        """
        try:
            return cls._member_map_[name.upper()]
        except KeyError:
            raise AttributeError(name)


class AliasPatternType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of alias pattern
    """

    #: NotSpecified is not allowed.
    NOT_SPECIFIED = "NotSpecified"
    #: Extract is the only allowed value.
    EXTRACT = "Extract"

class AliasType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of the alias.
    """

    #: Alias type is unknown (same as not providing alias type).
    NOT_SPECIFIED = "NotSpecified"
    #: Alias value is not secret.
    PLAIN_TEXT = "PlainText"
    #: Alias value is secret.
    MASK = "Mask"

class ChangeType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Type of change that will be made to the resource when the deployment is executed.
    """

    #: The resource does not exist in the current state but is present in the desired state. The
    #: resource will be created when the deployment is executed.
    CREATE = "Create"
    #: The resource exists in the current state and is missing from the desired state. The resource
    #: will be deleted when the deployment is executed.
    DELETE = "Delete"
    #: The resource exists in the current state and is missing from the desired state. The resource
    #: will not be deployed or modified when the deployment is executed.
    IGNORE = "Ignore"
    #: The resource exists in the current state and the desired state and will be redeployed when the
    #: deployment is executed. The properties of the resource may or may not change.
    DEPLOY = "Deploy"
    #: The resource exists in the current state and the desired state and will be redeployed when the
    #: deployment is executed. The properties of the resource will not change.
    NO_CHANGE = "NoChange"
    #: The resource exists in the current state and the desired state and will be redeployed when the
    #: deployment is executed. The properties of the resource will change.
    MODIFY = "Modify"

class DeploymentMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The mode that is used to deploy resources. This value can be either Incremental or Complete. In
    Incremental mode, resources are deployed without deleting existing resources that are not
    included in the template. In Complete mode, resources are deployed and existing resources in
    the resource group that are not included in the template are deleted. Be careful when using
    Complete mode as you may unintentionally delete resources.
    """

    INCREMENTAL = "Incremental"
    COMPLETE = "Complete"

class OnErrorDeploymentType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The deployment on error behavior type. Possible values are LastSuccessful and
    SpecificDeployment.
    """

    LAST_SUCCESSFUL = "LastSuccessful"
    SPECIFIC_DEPLOYMENT = "SpecificDeployment"

class PropertyChangeType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of property change.
    """

    #: The property does not exist in the current state but is present in the desired state. The
    #: property will be created when the deployment is executed.
    CREATE = "Create"
    #: The property exists in the current state and is missing from the desired state. It will be
    #: deleted when the deployment is executed.
    DELETE = "Delete"
    #: The property exists in both current and desired state and is different. The value of the
    #: property will change when the deployment is executed.
    MODIFY = "Modify"
    #: The property is an array and contains nested changes.
    ARRAY = "Array"

class ProvisioningOperation(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The name of the current provisioning operation.
    """

    #: The provisioning operation is not specified.
    NOT_SPECIFIED = "NotSpecified"
    #: The provisioning operation is create.
    CREATE = "Create"
    #: The provisioning operation is delete.
    DELETE = "Delete"
    #: The provisioning operation is waiting.
    WAITING = "Waiting"
    #: The provisioning operation is waiting Azure async operation.
    AZURE_ASYNC_OPERATION_WAITING = "AzureAsyncOperationWaiting"
    #: The provisioning operation is waiting for resource cache.
    RESOURCE_CACHE_WAITING = "ResourceCacheWaiting"
    #: The provisioning operation is action.
    ACTION = "Action"
    #: The provisioning operation is read.
    READ = "Read"
    #: The provisioning operation is evaluate output.
    EVALUATE_DEPLOYMENT_OUTPUT = "EvaluateDeploymentOutput"
    #: The provisioning operation is cleanup. This operation is part of the 'complete' mode
    #: deployment.
    DEPLOYMENT_CLEANUP = "DeploymentCleanup"

class ResourceIdentityType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The identity type.
    """

    SYSTEM_ASSIGNED = "SystemAssigned"
    USER_ASSIGNED = "UserAssigned"
    SYSTEM_ASSIGNED_USER_ASSIGNED = "SystemAssigned, UserAssigned"
    NONE = "None"

class TagsPatchOperation(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The operation type for the patch API.
    """

    #: The 'replace' option replaces the entire set of existing tags with a new set.
    REPLACE = "Replace"
    #: The 'merge' option allows adding tags with new names and updating the values of tags with
    #: existing names.
    MERGE = "Merge"
    #: The 'delete' option allows selectively deleting tags based on given names or name/value pairs.
    DELETE = "Delete"

class WhatIfResultFormat(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The format of the What-If results
    """

    RESOURCE_ID_ONLY = "ResourceIdOnly"
    FULL_RESOURCE_PAYLOADS = "FullResourcePayloads"
