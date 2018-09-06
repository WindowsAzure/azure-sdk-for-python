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


class SkuName(str, Enum):

    f0 = "F0"
    s1 = "S1"


class SkuTier(str, Enum):

    free = "Free"
    standard = "Standard"


class Kind(str, Enum):

    sdk = "sdk"
    designer = "designer"
    bot = "bot"
    function = "function"


class EnterpriseChannelState(str, Enum):

    creating = "Creating"
    create_failed = "CreateFailed"
    started = "Started"
    starting = "Starting"
    start_failed = "StartFailed"
    stopped = "Stopped"
    stopping = "Stopping"
    stop_failed = "StopFailed"
    deleting = "Deleting"
    delete_failed = "DeleteFailed"


class EnterpriseChannelNodeState(str, Enum):

    creating = "Creating"
    create_failed = "CreateFailed"
    started = "Started"
    starting = "Starting"
    start_failed = "StartFailed"
    stopped = "Stopped"
    stopping = "Stopping"
    stop_failed = "StopFailed"
    deleting = "Deleting"
    delete_failed = "DeleteFailed"


class ChannelName(str, Enum):

    facebook_channel = "FacebookChannel"
    email_channel = "EmailChannel"
    kik_channel = "KikChannel"
    telegram_channel = "TelegramChannel"
    slack_channel = "SlackChannel"
    ms_teams_channel = "MsTeamsChannel"
    skype_channel = "SkypeChannel"
    web_chat_channel = "WebChatChannel"
    direct_line_channel = "DirectLineChannel"
    sms_channel = "SmsChannel"
