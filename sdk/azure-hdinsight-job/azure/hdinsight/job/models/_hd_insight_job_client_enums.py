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

from enum import Enum


class ApplicationState(str, Enum):

    new = "NEW"
    new_saving = "NEW_SAVING"
    submitted = "SUBMITTED"
    accepted = "ACCEPTED"
    running = "RUNNING"
    finished = "FINISHED"
    finishing = "FINISHING"
    failed = "FAILED"
    killed = "KILLED"


class SessionJobKind(str, Enum):

    spark = "spark"
    pyspark = "pyspark"
    sparkr = "sparkr"
    sql = "sql"
