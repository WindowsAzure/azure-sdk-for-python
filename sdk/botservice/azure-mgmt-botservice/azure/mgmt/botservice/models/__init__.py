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
    from ._models_py3 import AlexaChannel
    from ._models_py3 import AlexaChannelProperties
    from ._models_py3 import Bot
    from ._models_py3 import BotChannel
    from ._models_py3 import BotProperties
    from ._models_py3 import Channel
    from ._models_py3 import CheckNameAvailabilityRequestBody
    from ._models_py3 import CheckNameAvailabilityResponseBody
    from ._models_py3 import ConnectionItemName
    from ._models_py3 import ConnectionSetting
    from ._models_py3 import ConnectionSettingParameter
    from ._models_py3 import ConnectionSettingProperties
    from ._models_py3 import DirectLineChannel
    from ._models_py3 import DirectLineChannelProperties
    from ._models_py3 import DirectLineSite
    from ._models_py3 import DirectLineSpeechChannel
    from ._models_py3 import DirectLineSpeechChannelProperties
    from ._models_py3 import EmailChannel
    from ._models_py3 import EmailChannelProperties
    from ._models_py3 import Error, ErrorException
    from ._models_py3 import ErrorBody
    from ._models_py3 import FacebookChannel
    from ._models_py3 import FacebookChannelProperties
    from ._models_py3 import FacebookPage
    from ._models_py3 import KikChannel
    from ._models_py3 import KikChannelProperties
    from ._models_py3 import LineChannel
    from ._models_py3 import LineChannelProperties
    from ._models_py3 import LineRegistration
    from ._models_py3 import MsTeamsChannel
    from ._models_py3 import MsTeamsChannelProperties
    from ._models_py3 import OperationDisplayInfo
    from ._models_py3 import OperationEntity
    from ._models_py3 import Resource
    from ._models_py3 import ServiceProvider
    from ._models_py3 import ServiceProviderParameter
    from ._models_py3 import ServiceProviderProperties
    from ._models_py3 import ServiceProviderResponseList
    from ._models_py3 import SiteInfo
    from ._models_py3 import Sku
    from ._models_py3 import SkypeChannel
    from ._models_py3 import SkypeChannelProperties
    from ._models_py3 import SlackChannel
    from ._models_py3 import SlackChannelProperties
    from ._models_py3 import SmsChannel
    from ._models_py3 import SmsChannelProperties
    from ._models_py3 import TelegramChannel
    from ._models_py3 import TelegramChannelProperties
    from ._models_py3 import WebChatChannel
    from ._models_py3 import WebChatChannelProperties
    from ._models_py3 import WebChatSite
except (SyntaxError, ImportError):
    from ._models import AlexaChannel
    from ._models import AlexaChannelProperties
    from ._models import Bot
    from ._models import BotChannel
    from ._models import BotProperties
    from ._models import Channel
    from ._models import CheckNameAvailabilityRequestBody
    from ._models import CheckNameAvailabilityResponseBody
    from ._models import ConnectionItemName
    from ._models import ConnectionSetting
    from ._models import ConnectionSettingParameter
    from ._models import ConnectionSettingProperties
    from ._models import DirectLineChannel
    from ._models import DirectLineChannelProperties
    from ._models import DirectLineSite
    from ._models import DirectLineSpeechChannel
    from ._models import DirectLineSpeechChannelProperties
    from ._models import EmailChannel
    from ._models import EmailChannelProperties
    from ._models import Error, ErrorException
    from ._models import ErrorBody
    from ._models import FacebookChannel
    from ._models import FacebookChannelProperties
    from ._models import FacebookPage
    from ._models import KikChannel
    from ._models import KikChannelProperties
    from ._models import LineChannel
    from ._models import LineChannelProperties
    from ._models import LineRegistration
    from ._models import MsTeamsChannel
    from ._models import MsTeamsChannelProperties
    from ._models import OperationDisplayInfo
    from ._models import OperationEntity
    from ._models import Resource
    from ._models import ServiceProvider
    from ._models import ServiceProviderParameter
    from ._models import ServiceProviderProperties
    from ._models import ServiceProviderResponseList
    from ._models import SiteInfo
    from ._models import Sku
    from ._models import SkypeChannel
    from ._models import SkypeChannelProperties
    from ._models import SlackChannel
    from ._models import SlackChannelProperties
    from ._models import SmsChannel
    from ._models import SmsChannelProperties
    from ._models import TelegramChannel
    from ._models import TelegramChannelProperties
    from ._models import WebChatChannel
    from ._models import WebChatChannelProperties
    from ._models import WebChatSite
from ._paged_models import BotChannelPaged
from ._paged_models import BotPaged
from ._paged_models import ConnectionSettingPaged
from ._paged_models import OperationEntityPaged
from ._azure_bot_service_enums import (
    SkuName,
    SkuTier,
    Kind,
    Key,
    ChannelName,
    RegenerateKeysChannelName,
)

__all__ = [
    'AlexaChannel',
    'AlexaChannelProperties',
    'Bot',
    'BotChannel',
    'BotProperties',
    'Channel',
    'CheckNameAvailabilityRequestBody',
    'CheckNameAvailabilityResponseBody',
    'ConnectionItemName',
    'ConnectionSetting',
    'ConnectionSettingParameter',
    'ConnectionSettingProperties',
    'DirectLineChannel',
    'DirectLineChannelProperties',
    'DirectLineSite',
    'DirectLineSpeechChannel',
    'DirectLineSpeechChannelProperties',
    'EmailChannel',
    'EmailChannelProperties',
    'Error', 'ErrorException',
    'ErrorBody',
    'FacebookChannel',
    'FacebookChannelProperties',
    'FacebookPage',
    'KikChannel',
    'KikChannelProperties',
    'LineChannel',
    'LineChannelProperties',
    'LineRegistration',
    'MsTeamsChannel',
    'MsTeamsChannelProperties',
    'OperationDisplayInfo',
    'OperationEntity',
    'Resource',
    'ServiceProvider',
    'ServiceProviderParameter',
    'ServiceProviderProperties',
    'ServiceProviderResponseList',
    'SiteInfo',
    'Sku',
    'SkypeChannel',
    'SkypeChannelProperties',
    'SlackChannel',
    'SlackChannelProperties',
    'SmsChannel',
    'SmsChannelProperties',
    'TelegramChannel',
    'TelegramChannelProperties',
    'WebChatChannel',
    'WebChatChannelProperties',
    'WebChatSite',
    'BotPaged',
    'BotChannelPaged',
    'OperationEntityPaged',
    'ConnectionSettingPaged',
    'SkuName',
    'SkuTier',
    'Kind',
    'Key',
    'ChannelName',
    'RegenerateKeysChannelName',
]
