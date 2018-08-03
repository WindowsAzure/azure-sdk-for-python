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


class BotProperties(Model):
    """The parameters to provide for the Bot.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param display_name: The Name of the bot
    :type display_name: str
    :param description: The description of the bot
    :type description: str
    :param icon_url: The Icon Url of the bot
    :type icon_url: str
    :param endpoint: The bot's endpoint
    :type endpoint: str
    :ivar endpoint_version: The bot's endpoint version
    :vartype endpoint_version: str
    :param msa_app_id: Microsoft App Id for the bot
    :type msa_app_id: str
    :ivar configured_channels: Collection of channels for which the bot is
     configured
    :vartype configured_channels: list[str]
    :ivar enabled_channels: Collection of channels for which the bot is
     enabled
    :vartype enabled_channels: list[str]
    :param developer_app_insight_key: The Application Insights key
    :type developer_app_insight_key: str
    :param developer_app_insights_api_key: The Application Insights Api Key
    :type developer_app_insights_api_key: str
    :param developer_app_insights_application_id: The Application Insights App
     Id
    :type developer_app_insights_application_id: str
    :param luis_app_ids: Collection of LUIS App Ids
    :type luis_app_ids: list[str]
    :param luis_key: The LUIS Key
    :type luis_key: str
    """

    _validation = {
        'display_name': {'required': True},
        'endpoint': {'required': True},
        'endpoint_version': {'readonly': True},
        'msa_app_id': {'required': True},
        'configured_channels': {'readonly': True},
        'enabled_channels': {'readonly': True},
    }

    _attribute_map = {
        'display_name': {'key': 'displayName', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'icon_url': {'key': 'iconUrl', 'type': 'str'},
        'endpoint': {'key': 'endpoint', 'type': 'str'},
        'endpoint_version': {'key': 'endpointVersion', 'type': 'str'},
        'msa_app_id': {'key': 'msaAppId', 'type': 'str'},
        'configured_channels': {'key': 'configuredChannels', 'type': '[str]'},
        'enabled_channels': {'key': 'enabledChannels', 'type': '[str]'},
        'developer_app_insight_key': {'key': 'developerAppInsightKey', 'type': 'str'},
        'developer_app_insights_api_key': {'key': 'developerAppInsightsApiKey', 'type': 'str'},
        'developer_app_insights_application_id': {'key': 'developerAppInsightsApplicationId', 'type': 'str'},
        'luis_app_ids': {'key': 'luisAppIds', 'type': '[str]'},
        'luis_key': {'key': 'luisKey', 'type': 'str'},
    }

    def __init__(self, display_name, endpoint, msa_app_id, description=None, icon_url=None, developer_app_insight_key=None, developer_app_insights_api_key=None, developer_app_insights_application_id=None, luis_app_ids=None, luis_key=None):
        super(BotProperties, self).__init__()
        self.display_name = display_name
        self.description = description
        self.icon_url = icon_url
        self.endpoint = endpoint
        self.endpoint_version = None
        self.msa_app_id = msa_app_id
        self.configured_channels = None
        self.enabled_channels = None
        self.developer_app_insight_key = developer_app_insight_key
        self.developer_app_insights_api_key = developer_app_insights_api_key
        self.developer_app_insights_application_id = developer_app_insights_application_id
        self.luis_app_ids = luis_app_ids
        self.luis_key = luis_key
