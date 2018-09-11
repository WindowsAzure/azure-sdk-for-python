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


class SystemReflectionMethodInfo(Model):
    """SystemReflectionMethodInfo.

    :param member_type: Possible values include: 'Constructor', 'Event',
     'Field', 'Method', 'Property', 'TypeInfo', 'Custom', 'NestedType', 'All'
    :type member_type: str or ~azure.monitor.models.enum
    :param return_type:
    :type return_type: ~azure.monitor.models.SystemType
    :param return_parameter:
    :type return_parameter:
     ~azure.monitor.models.SystemReflectionParameterInfo
    :param return_type_custom_attributes:
    :type return_type_custom_attributes: object
    :param method_implementation_flags: Possible values include: 'Managed',
     'IL', 'Native', 'OPTIL', 'Runtime', 'CodeTypeMask', 'Unmanaged',
     'ManagedMask', 'NoInlining', 'ForwardRef', 'Synchronized',
     'NoOptimization', 'PreserveSig', 'AggressiveInlining', 'InternalCall',
     'MaxMethodImplVal'
    :type method_implementation_flags: str or ~azure.monitor.models.enum
    :param method_handle:
    :type method_handle: ~azure.monitor.models.SystemRuntimeMethodHandle
    :param attributes: Possible values include: 'ReuseSlot', 'PrivateScope',
     'Private', 'FamANDAssem', 'Assembly', 'Family', 'FamORAssem', 'Public',
     'MemberAccessMask', 'UnmanagedExport', 'Static', 'Final', 'Virtual',
     'HideBySig', 'NewSlot', 'VtableLayoutMask', 'CheckAccessOnOverride',
     'Abstract', 'SpecialName', 'RTSpecialName', 'PinvokeImpl', 'HasSecurity',
     'RequireSecObject', 'ReservedMask'
    :type attributes: str or ~azure.monitor.models.enum
    :param calling_convention: Possible values include: 'Standard', 'VarArgs',
     'Any', 'HasThis', 'ExplicitThis'
    :type calling_convention: str or ~azure.monitor.models.enum
    :param is_generic_method_definition:
    :type is_generic_method_definition: bool
    :param contains_generic_parameters:
    :type contains_generic_parameters: bool
    :param is_generic_method:
    :type is_generic_method: bool
    :param is_security_critical:
    :type is_security_critical: bool
    :param is_security_safe_critical:
    :type is_security_safe_critical: bool
    :param is_security_transparent:
    :type is_security_transparent: bool
    :param is_public:
    :type is_public: bool
    :param is_private:
    :type is_private: bool
    :param is_family:
    :type is_family: bool
    :param is_assembly:
    :type is_assembly: bool
    :param is_family_and_assembly:
    :type is_family_and_assembly: bool
    :param is_family_or_assembly:
    :type is_family_or_assembly: bool
    :param is_static:
    :type is_static: bool
    :param is_final:
    :type is_final: bool
    :param is_virtual:
    :type is_virtual: bool
    :param is_hide_by_sig:
    :type is_hide_by_sig: bool
    :param is_abstract:
    :type is_abstract: bool
    :param is_special_name:
    :type is_special_name: bool
    :param is_constructor:
    :type is_constructor: bool
    :param name:
    :type name: str
    :param declaring_type:
    :type declaring_type: ~azure.monitor.models.SystemType
    :param reflected_type:
    :type reflected_type: ~azure.monitor.models.SystemType
    :param custom_attributes:
    :type custom_attributes:
     list[~azure.monitor.models.SystemReflectionCustomAttributeData]
    :param metadata_token:
    :type metadata_token: int
    :param module:
    :type module: ~azure.monitor.models.SystemReflectionModule
    """

    _attribute_map = {
        'member_type': {'key': 'MemberType', 'type': 'str'},
        'return_type': {'key': 'ReturnType', 'type': 'SystemType'},
        'return_parameter': {'key': 'ReturnParameter', 'type': 'SystemReflectionParameterInfo'},
        'return_type_custom_attributes': {'key': 'ReturnTypeCustomAttributes', 'type': 'object'},
        'method_implementation_flags': {'key': 'MethodImplementationFlags', 'type': 'str'},
        'method_handle': {'key': 'MethodHandle', 'type': 'SystemRuntimeMethodHandle'},
        'attributes': {'key': 'Attributes', 'type': 'str'},
        'calling_convention': {'key': 'CallingConvention', 'type': 'str'},
        'is_generic_method_definition': {'key': 'IsGenericMethodDefinition', 'type': 'bool'},
        'contains_generic_parameters': {'key': 'ContainsGenericParameters', 'type': 'bool'},
        'is_generic_method': {'key': 'IsGenericMethod', 'type': 'bool'},
        'is_security_critical': {'key': 'IsSecurityCritical', 'type': 'bool'},
        'is_security_safe_critical': {'key': 'IsSecuritySafeCritical', 'type': 'bool'},
        'is_security_transparent': {'key': 'IsSecurityTransparent', 'type': 'bool'},
        'is_public': {'key': 'IsPublic', 'type': 'bool'},
        'is_private': {'key': 'IsPrivate', 'type': 'bool'},
        'is_family': {'key': 'IsFamily', 'type': 'bool'},
        'is_assembly': {'key': 'IsAssembly', 'type': 'bool'},
        'is_family_and_assembly': {'key': 'IsFamilyAndAssembly', 'type': 'bool'},
        'is_family_or_assembly': {'key': 'IsFamilyOrAssembly', 'type': 'bool'},
        'is_static': {'key': 'IsStatic', 'type': 'bool'},
        'is_final': {'key': 'IsFinal', 'type': 'bool'},
        'is_virtual': {'key': 'IsVirtual', 'type': 'bool'},
        'is_hide_by_sig': {'key': 'IsHideBySig', 'type': 'bool'},
        'is_abstract': {'key': 'IsAbstract', 'type': 'bool'},
        'is_special_name': {'key': 'IsSpecialName', 'type': 'bool'},
        'is_constructor': {'key': 'IsConstructor', 'type': 'bool'},
        'name': {'key': 'Name', 'type': 'str'},
        'declaring_type': {'key': 'DeclaringType', 'type': 'SystemType'},
        'reflected_type': {'key': 'ReflectedType', 'type': 'SystemType'},
        'custom_attributes': {'key': 'CustomAttributes', 'type': '[SystemReflectionCustomAttributeData]'},
        'metadata_token': {'key': 'MetadataToken', 'type': 'int'},
        'module': {'key': 'Module', 'type': 'SystemReflectionModule'},
    }

    def __init__(self, *, member_type=None, return_type=None, return_parameter=None, return_type_custom_attributes=None, method_implementation_flags=None, method_handle=None, attributes=None, calling_convention=None, is_generic_method_definition: bool=None, contains_generic_parameters: bool=None, is_generic_method: bool=None, is_security_critical: bool=None, is_security_safe_critical: bool=None, is_security_transparent: bool=None, is_public: bool=None, is_private: bool=None, is_family: bool=None, is_assembly: bool=None, is_family_and_assembly: bool=None, is_family_or_assembly: bool=None, is_static: bool=None, is_final: bool=None, is_virtual: bool=None, is_hide_by_sig: bool=None, is_abstract: bool=None, is_special_name: bool=None, is_constructor: bool=None, name: str=None, declaring_type=None, reflected_type=None, custom_attributes=None, metadata_token: int=None, module=None, **kwargs) -> None:
        super(SystemReflectionMethodInfo, self).__init__(**kwargs)
        self.member_type = member_type
        self.return_type = return_type
        self.return_parameter = return_parameter
        self.return_type_custom_attributes = return_type_custom_attributes
        self.method_implementation_flags = method_implementation_flags
        self.method_handle = method_handle
        self.attributes = attributes
        self.calling_convention = calling_convention
        self.is_generic_method_definition = is_generic_method_definition
        self.contains_generic_parameters = contains_generic_parameters
        self.is_generic_method = is_generic_method
        self.is_security_critical = is_security_critical
        self.is_security_safe_critical = is_security_safe_critical
        self.is_security_transparent = is_security_transparent
        self.is_public = is_public
        self.is_private = is_private
        self.is_family = is_family
        self.is_assembly = is_assembly
        self.is_family_and_assembly = is_family_and_assembly
        self.is_family_or_assembly = is_family_or_assembly
        self.is_static = is_static
        self.is_final = is_final
        self.is_virtual = is_virtual
        self.is_hide_by_sig = is_hide_by_sig
        self.is_abstract = is_abstract
        self.is_special_name = is_special_name
        self.is_constructor = is_constructor
        self.name = name
        self.declaring_type = declaring_type
        self.reflected_type = reflected_type
        self.custom_attributes = custom_attributes
        self.metadata_token = metadata_token
        self.module = module
