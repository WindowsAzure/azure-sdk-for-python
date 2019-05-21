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


class OSType(str, Enum):

    linux = "Linux"
    windows = "Windows"


class OpenShiftContainerServiceVMSize(str, Enum):

    standard_d2s_v3 = "Standard_D2s_v3"
    standard_d4s_v3 = "Standard_D4s_v3"
    standard_d8s_v3 = "Standard_D8s_v3"
    standard_d16s_v3 = "Standard_D16s_v3"
    standard_d32s_v3 = "Standard_D32s_v3"
    standard_d64s_v3 = "Standard_D64s_v3"
    standard_ds4_v2 = "Standard_DS4_v2"
    standard_ds5_v2 = "Standard_DS5_v2"
    standard_f8s_v2 = "Standard_F8s_v2"
    standard_f16s_v2 = "Standard_F16s_v2"
    standard_f32s_v2 = "Standard_F32s_v2"
    standard_f64s_v2 = "Standard_F64s_v2"
    standard_f72s_v2 = "Standard_F72s_v2"
    standard_f8s = "Standard_F8s"
    standard_f16s = "Standard_F16s"
    standard_e4s_v3 = "Standard_E4s_v3"
    standard_e8s_v3 = "Standard_E8s_v3"
    standard_e16s_v3 = "Standard_E16s_v3"
    standard_e20s_v3 = "Standard_E20s_v3"
    standard_e32s_v3 = "Standard_E32s_v3"
    standard_e64s_v3 = "Standard_E64s_v3"
    standard_gs2 = "Standard_GS2"
    standard_gs3 = "Standard_GS3"
    standard_gs4 = "Standard_GS4"
    standard_gs5 = "Standard_GS5"
    standard_ds12_v2 = "Standard_DS12_v2"
    standard_ds13_v2 = "Standard_DS13_v2"
    standard_ds14_v2 = "Standard_DS14_v2"
    standard_ds15_v2 = "Standard_DS15_v2"
    standard_l4s = "Standard_L4s"
    standard_l8s = "Standard_L8s"
    standard_l16s = "Standard_L16s"
    standard_l32s = "Standard_L32s"


class OpenShiftAgentPoolProfileRole(str, Enum):

    compute = "compute"
    infra = "infra"
