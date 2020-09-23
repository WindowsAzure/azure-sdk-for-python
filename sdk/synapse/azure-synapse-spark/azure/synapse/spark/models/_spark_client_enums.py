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


class PluginCurrentState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    PREPARATION = "Preparation"
    RESOURCE_ACQUISITION = "ResourceAcquisition"
    QUEUED = "Queued"
    SUBMISSION = "Submission"
    MONITORING = "Monitoring"
    CLEANUP = "Cleanup"
    ENDED = "Ended"

class SchedulerCurrentState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    QUEUED = "Queued"
    SCHEDULED = "Scheduled"
    ENDED = "Ended"

class SparkBatchJobResultType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The Spark batch job result.
    """

    UNCERTAIN = "Uncertain"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELLED = "Cancelled"

class SparkErrorSource(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    SYSTEM = "System"
    USER = "User"
    UNKNOWN = "Unknown"
    DEPENDENCY = "Dependency"

class SparkJobType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The job type.
    """

    SPARK_BATCH = "SparkBatch"
    SPARK_SESSION = "SparkSession"

class SparkSessionResultType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    UNCERTAIN = "Uncertain"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CANCELLED = "Cancelled"

class SparkStatementLanguageType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    SPARK = "spark"
    PYSPARK = "pyspark"
    DOTNETSPARK = "dotnetspark"
    SQL = "sql"
