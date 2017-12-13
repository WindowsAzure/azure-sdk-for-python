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

from azure.cognitiveservices.language.spellcheck import SpellCheckAPI
from msrest.authentication import CognitiveServicesCredentials

from azure_devtools.scenario_tests import ReplayableTest, AzureTestError

from devtools_testutils import mgmt_settings_fake as fake_settings


class SpellCheckTest(ReplayableTest):
    FILTER_HEADERS = ReplayableTest.FILTER_HEADERS + ['Ocp-Apim-Subscription-Key']

    def __init__(self, method_name):
        self._fake_settings, self._real_settings = self._load_settings()
        super(SpellCheckTest, self).__init__(method_name)

    @property
    def settings(self):
        if self.is_live:
            if self._real_settings:
                return self._real_settings
            else:
                raise AzureTestError('Need a mgmt_settings_real.py file to run tests live.')
        else:
            return self._fake_settings

    def _load_settings(self):
        try:
            from devtools_testutils import mgmt_settings_real as real_settings
            return fake_settings, real_settings
        except ImportError:
            return fake_settings, None

    def test_spell_check(self):
        credentials = CognitiveServicesCredentials(
            self.settings.CS_SUBSCRIPTION_KEY
        )
        text_analytics = SpellCheckAPI(credentials=credentials)
        response = text_analytics.spell_check_method(
            "cognituve services"
        )
        self.assertEquals(response.flagged_tokens[0].token, "cognituve")
        self.assertEquals(response.flagged_tokens[0].suggestions[0].suggestion, "cognitive")



