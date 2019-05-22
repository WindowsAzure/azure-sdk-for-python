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


class ContainerServiceStorageProfileTypes(str, Enum):

    storage_account = "StorageAccount"
    managed_disks = "ManagedDisks"


class ContainerServiceVMSizeTypes(str, Enum):

    standard_a1 = "Standard_A1"
    standard_a10 = "Standard_A10"
    standard_a11 = "Standard_A11"
    standard_a1_v2 = "Standard_A1_v2"
    standard_a2 = "Standard_A2"
    standard_a2_v2 = "Standard_A2_v2"
    standard_a2m_v2 = "Standard_A2m_v2"
    standard_a3 = "Standard_A3"
    standard_a4 = "Standard_A4"
    standard_a4_v2 = "Standard_A4_v2"
    standard_a4m_v2 = "Standard_A4m_v2"
    standard_a5 = "Standard_A5"
    standard_a6 = "Standard_A6"
    standard_a7 = "Standard_A7"
    standard_a8 = "Standard_A8"
    standard_a8_v2 = "Standard_A8_v2"
    standard_a8m_v2 = "Standard_A8m_v2"
    standard_a9 = "Standard_A9"
    standard_b2ms = "Standard_B2ms"
    standard_b2s = "Standard_B2s"
    standard_b4ms = "Standard_B4ms"
    standard_b8ms = "Standard_B8ms"
    standard_d1 = "Standard_D1"
    standard_d11 = "Standard_D11"
    standard_d11_v2 = "Standard_D11_v2"
    standard_d11_v2_promo = "Standard_D11_v2_Promo"
    standard_d12 = "Standard_D12"
    standard_d12_v2 = "Standard_D12_v2"
    standard_d12_v2_promo = "Standard_D12_v2_Promo"
    standard_d13 = "Standard_D13"
    standard_d13_v2 = "Standard_D13_v2"
    standard_d13_v2_promo = "Standard_D13_v2_Promo"
    standard_d14 = "Standard_D14"
    standard_d14_v2 = "Standard_D14_v2"
    standard_d14_v2_promo = "Standard_D14_v2_Promo"
    standard_d15_v2 = "Standard_D15_v2"
    standard_d16_v3 = "Standard_D16_v3"
    standard_d16s_v3 = "Standard_D16s_v3"
    standard_d1_v2 = "Standard_D1_v2"
    standard_d2 = "Standard_D2"
    standard_d2_v2 = "Standard_D2_v2"
    standard_d2_v2_promo = "Standard_D2_v2_Promo"
    standard_d2_v3 = "Standard_D2_v3"
    standard_d2s_v3 = "Standard_D2s_v3"
    standard_d3 = "Standard_D3"
    standard_d32_v3 = "Standard_D32_v3"
    standard_d32s_v3 = "Standard_D32s_v3"
    standard_d3_v2 = "Standard_D3_v2"
    standard_d3_v2_promo = "Standard_D3_v2_Promo"
    standard_d4 = "Standard_D4"
    standard_d4_v2 = "Standard_D4_v2"
    standard_d4_v2_promo = "Standard_D4_v2_Promo"
    standard_d4_v3 = "Standard_D4_v3"
    standard_d4s_v3 = "Standard_D4s_v3"
    standard_d5_v2 = "Standard_D5_v2"
    standard_d5_v2_promo = "Standard_D5_v2_Promo"
    standard_d64_v3 = "Standard_D64_v3"
    standard_d64s_v3 = "Standard_D64s_v3"
    standard_d8_v3 = "Standard_D8_v3"
    standard_d8s_v3 = "Standard_D8s_v3"
    standard_ds1 = "Standard_DS1"
    standard_ds11 = "Standard_DS11"
    standard_ds11_v2 = "Standard_DS11_v2"
    standard_ds11_v2_promo = "Standard_DS11_v2_Promo"
    standard_ds12 = "Standard_DS12"
    standard_ds12_v2 = "Standard_DS12_v2"
    standard_ds12_v2_promo = "Standard_DS12_v2_Promo"
    standard_ds13 = "Standard_DS13"
    standard_ds13_2_v2 = "Standard_DS13-2_v2"
    standard_ds13_4_v2 = "Standard_DS13-4_v2"
    standard_ds13_v2 = "Standard_DS13_v2"
    standard_ds13_v2_promo = "Standard_DS13_v2_Promo"
    standard_ds14 = "Standard_DS14"
    standard_ds14_4_v2 = "Standard_DS14-4_v2"
    standard_ds14_8_v2 = "Standard_DS14-8_v2"
    standard_ds14_v2 = "Standard_DS14_v2"
    standard_ds14_v2_promo = "Standard_DS14_v2_Promo"
    standard_ds15_v2 = "Standard_DS15_v2"
    standard_ds1_v2 = "Standard_DS1_v2"
    standard_ds2 = "Standard_DS2"
    standard_ds2_v2 = "Standard_DS2_v2"
    standard_ds2_v2_promo = "Standard_DS2_v2_Promo"
    standard_ds3 = "Standard_DS3"
    standard_ds3_v2 = "Standard_DS3_v2"
    standard_ds3_v2_promo = "Standard_DS3_v2_Promo"
    standard_ds4 = "Standard_DS4"
    standard_ds4_v2 = "Standard_DS4_v2"
    standard_ds4_v2_promo = "Standard_DS4_v2_Promo"
    standard_ds5_v2 = "Standard_DS5_v2"
    standard_ds5_v2_promo = "Standard_DS5_v2_Promo"
    standard_e16_v3 = "Standard_E16_v3"
    standard_e16s_v3 = "Standard_E16s_v3"
    standard_e2_v3 = "Standard_E2_v3"
    standard_e2s_v3 = "Standard_E2s_v3"
    standard_e32_16s_v3 = "Standard_E32-16s_v3"
    standard_e32_8s_v3 = "Standard_E32-8s_v3"
    standard_e32_v3 = "Standard_E32_v3"
    standard_e32s_v3 = "Standard_E32s_v3"
    standard_e4_v3 = "Standard_E4_v3"
    standard_e4s_v3 = "Standard_E4s_v3"
    standard_e64_16s_v3 = "Standard_E64-16s_v3"
    standard_e64_32s_v3 = "Standard_E64-32s_v3"
    standard_e64_v3 = "Standard_E64_v3"
    standard_e64s_v3 = "Standard_E64s_v3"
    standard_e8_v3 = "Standard_E8_v3"
    standard_e8s_v3 = "Standard_E8s_v3"
    standard_f1 = "Standard_F1"
    standard_f16 = "Standard_F16"
    standard_f16s = "Standard_F16s"
    standard_f16s_v2 = "Standard_F16s_v2"
    standard_f1s = "Standard_F1s"
    standard_f2 = "Standard_F2"
    standard_f2s = "Standard_F2s"
    standard_f2s_v2 = "Standard_F2s_v2"
    standard_f32s_v2 = "Standard_F32s_v2"
    standard_f4 = "Standard_F4"
    standard_f4s = "Standard_F4s"
    standard_f4s_v2 = "Standard_F4s_v2"
    standard_f64s_v2 = "Standard_F64s_v2"
    standard_f72s_v2 = "Standard_F72s_v2"
    standard_f8 = "Standard_F8"
    standard_f8s = "Standard_F8s"
    standard_f8s_v2 = "Standard_F8s_v2"
    standard_g1 = "Standard_G1"
    standard_g2 = "Standard_G2"
    standard_g3 = "Standard_G3"
    standard_g4 = "Standard_G4"
    standard_g5 = "Standard_G5"
    standard_gs1 = "Standard_GS1"
    standard_gs2 = "Standard_GS2"
    standard_gs3 = "Standard_GS3"
    standard_gs4 = "Standard_GS4"
    standard_gs4_4 = "Standard_GS4-4"
    standard_gs4_8 = "Standard_GS4-8"
    standard_gs5 = "Standard_GS5"
    standard_gs5_16 = "Standard_GS5-16"
    standard_gs5_8 = "Standard_GS5-8"
    standard_h16 = "Standard_H16"
    standard_h16m = "Standard_H16m"
    standard_h16mr = "Standard_H16mr"
    standard_h16r = "Standard_H16r"
    standard_h8 = "Standard_H8"
    standard_h8m = "Standard_H8m"
    standard_l16s = "Standard_L16s"
    standard_l32s = "Standard_L32s"
    standard_l4s = "Standard_L4s"
    standard_l8s = "Standard_L8s"
    standard_m128_32ms = "Standard_M128-32ms"
    standard_m128_64ms = "Standard_M128-64ms"
    standard_m128ms = "Standard_M128ms"
    standard_m128s = "Standard_M128s"
    standard_m64_16ms = "Standard_M64-16ms"
    standard_m64_32ms = "Standard_M64-32ms"
    standard_m64ms = "Standard_M64ms"
    standard_m64s = "Standard_M64s"
    standard_nc12 = "Standard_NC12"
    standard_nc12s_v2 = "Standard_NC12s_v2"
    standard_nc12s_v3 = "Standard_NC12s_v3"
    standard_nc24 = "Standard_NC24"
    standard_nc24r = "Standard_NC24r"
    standard_nc24rs_v2 = "Standard_NC24rs_v2"
    standard_nc24rs_v3 = "Standard_NC24rs_v3"
    standard_nc24s_v2 = "Standard_NC24s_v2"
    standard_nc24s_v3 = "Standard_NC24s_v3"
    standard_nc6 = "Standard_NC6"
    standard_nc6s_v2 = "Standard_NC6s_v2"
    standard_nc6s_v3 = "Standard_NC6s_v3"
    standard_nd12s = "Standard_ND12s"
    standard_nd24rs = "Standard_ND24rs"
    standard_nd24s = "Standard_ND24s"
    standard_nd6s = "Standard_ND6s"
    standard_nv12 = "Standard_NV12"
    standard_nv24 = "Standard_NV24"
    standard_nv6 = "Standard_NV6"


class OSType(str, Enum):

    linux = "Linux"
    windows = "Windows"


class AgentPoolType(str, Enum):

    virtual_machine_scale_sets = "VirtualMachineScaleSets"
    availability_set = "AvailabilitySet"


class NetworkPlugin(str, Enum):

    azure = "azure"
    kubenet = "kubenet"


class NetworkPolicy(str, Enum):

    calico = "calico"
    azure = "azure"


class LoadBalancerSku(str, Enum):

    standard = "standard"
    basic = "basic"


class ResourceIdentityType(str, Enum):

    system_assigned = "SystemAssigned"
    none = "None"
