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

try:
    from ._models_py3 import AzureResourceBase
    from ._models_py3 import ErrorAdditionalInfo
    from ._models_py3 import ErrorResponse
    from ._models_py3 import SystemData
    from ._models_py3 import TemplateSpecArtifact
    from ._models_py3 import TemplateSpecModel
    from ._models_py3 import TemplateSpecsError, TemplateSpecsErrorException
    from ._models_py3 import TemplateSpecTemplateArtifact
    from ._models_py3 import TemplateSpecUpdateModel
    from ._models_py3 import TemplateSpecVersionModel
    from ._models_py3 import TemplateSpecVersionUpdateModel
except (SyntaxError, ImportError):
    from ._models import AzureResourceBase
    from ._models import ErrorAdditionalInfo
    from ._models import ErrorResponse
    from ._models import SystemData
    from ._models import TemplateSpecArtifact
    from ._models import TemplateSpecModel
    from ._models import TemplateSpecsError, TemplateSpecsErrorException
    from ._models import TemplateSpecTemplateArtifact
    from ._models import TemplateSpecUpdateModel
    from ._models import TemplateSpecVersionModel
    from ._models import TemplateSpecVersionUpdateModel
from ._paged_models import TemplateSpecModelPaged
from ._paged_models import TemplateSpecVersionModelPaged
from ._template_specs_client_enums import (
    CreatedByType,
)

__all__ = [
    'AzureResourceBase',
    'ErrorAdditionalInfo',
    'ErrorResponse',
    'SystemData',
    'TemplateSpecArtifact',
    'TemplateSpecModel',
    'TemplateSpecsError', 'TemplateSpecsErrorException',
    'TemplateSpecTemplateArtifact',
    'TemplateSpecUpdateModel',
    'TemplateSpecVersionModel',
    'TemplateSpecVersionUpdateModel',
    'TemplateSpecModelPaged',
    'TemplateSpecVersionModelPaged',
    'CreatedByType',
]
