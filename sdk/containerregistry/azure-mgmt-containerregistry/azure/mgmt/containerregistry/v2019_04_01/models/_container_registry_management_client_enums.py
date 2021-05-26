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


class Architecture(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The OS architecture.
    """

    AMD64 = "amd64"
    X86 = "x86"
    ARM = "arm"

class BaseImageDependencyType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of the base image dependency.
    """

    BUILD_TIME = "BuildTime"
    RUN_TIME = "RunTime"

class BaseImageTriggerType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of the auto trigger for base image dependency updates.
    """

    ALL = "All"
    RUNTIME = "Runtime"

class OS(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The operating system type required for the run.
    """

    WINDOWS = "Windows"
    LINUX = "Linux"

class ProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The provisioning state of a run.
    """

    CREATING = "Creating"
    UPDATING = "Updating"
    DELETING = "Deleting"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELED = "Canceled"

class ResourceIdentityType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The identity type.
    """

    SYSTEM_ASSIGNED = "SystemAssigned"
    USER_ASSIGNED = "UserAssigned"
    SYSTEM_ASSIGNED_USER_ASSIGNED = "SystemAssigned, UserAssigned"
    NONE = "None"

class RunStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current status of the run.
    """

    QUEUED = "Queued"
    STARTED = "Started"
    RUNNING = "Running"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELED = "Canceled"
    ERROR = "Error"
    TIMEOUT = "Timeout"

class RunType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of run.
    """

    QUICK_BUILD = "QuickBuild"
    QUICK_RUN = "QuickRun"
    AUTO_BUILD = "AutoBuild"
    AUTO_RUN = "AutoRun"

class SecretObjectType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of the secret object which determines how the value of the secret object has to be
    interpreted.
    """

    OPAQUE = "Opaque"
    VAULTSECRET = "Vaultsecret"

class SourceControlType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of source control service.
    """

    GITHUB = "Github"
    VISUAL_STUDIO_TEAM_SERVICE = "VisualStudioTeamService"

class SourceRegistryLoginMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The authentication mode which determines the source registry login scope. The credentials for
    the source registry
    will be generated using the given scope. These credentials will be used to login to
    the source registry during the run.
    """

    NONE = "None"
    DEFAULT = "Default"

class SourceTriggerEvent(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    COMMIT = "commit"
    PULLREQUEST = "pullrequest"

class StepType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of the step.
    """

    DOCKER = "Docker"
    FILE_TASK = "FileTask"
    ENCODED_TASK = "EncodedTask"

class TaskStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current status of task.
    """

    DISABLED = "Disabled"
    ENABLED = "Enabled"

class TokenType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of Auth token.
    """

    PAT = "PAT"
    O_AUTH = "OAuth"

class TriggerStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current status of trigger.
    """

    DISABLED = "Disabled"
    ENABLED = "Enabled"

class Variant(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Variant of the CPU.
    """

    V6 = "v6"
    V7 = "v7"
    V8 = "v8"
