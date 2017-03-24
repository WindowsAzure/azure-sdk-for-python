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


class SkuName(Enum):

    f0 = "F0"
    p0 = "P0"
    p1 = "P1"
    p2 = "P2"
    s0 = "S0"
    s1 = "S1"
    s2 = "S2"
    s3 = "S3"
    s4 = "S4"
    s5 = "S5"
    s6 = "S6"


class SkuTier(Enum):

    free = "Free"
    standard = "Standard"
    premium = "Premium"


class Kind(Enum):

    academic = "Academic"
    bing_autosuggest = "Bing.Autosuggest"
    bing_search = "Bing.Search"
    bing_speech = "Bing.Speech"
    bing_spell_check = "Bing.SpellCheck"
    computer_vision = "ComputerVision"
    content_moderator = "ContentModerator"
    emotion = "Emotion"
    face = "Face"
    luis = "LUIS"
    recommendations = "Recommendations"
    speaker_recognition = "SpeakerRecognition"
    speech = "Speech"
    speech_translation = "SpeechTranslation"
    text_analytics = "TextAnalytics"
    text_translation = "TextTranslation"
    web_lm = "WebLM"


class ProvisioningState(Enum):

    creating = "Creating"
    resolving_dns = "ResolvingDNS"
    succeeded = "Succeeded"
    failed = "Failed"


class KeyName(Enum):

    key1 = "Key1"
    key2 = "Key2"
