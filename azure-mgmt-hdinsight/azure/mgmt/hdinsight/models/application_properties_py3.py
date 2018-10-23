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


class ApplicationProperties(Model):
    """The HDInsight cluster application GET response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param compute_profile: The list of roles in the cluster.
    :type compute_profile: ~azure.mgmt.hdinsight.models.ComputeProfile
    :param install_script_actions: The list of install script actions.
    :type install_script_actions:
     list[~azure.mgmt.hdinsight.models.RuntimeScriptAction]
    :param uninstall_script_actions: The list of uninstall script actions.
    :type uninstall_script_actions:
     list[~azure.mgmt.hdinsight.models.RuntimeScriptAction]
    :param https_endpoints: The list of application HTTPS endpoints.
    :type https_endpoints:
     list[~azure.mgmt.hdinsight.models.ApplicationGetHttpsEndpoint]
    :param ssh_endpoints: The list of application SSH endpoints.
    :type ssh_endpoints:
     list[~azure.mgmt.hdinsight.models.ApplicationGetEndpoint]
    :ivar provisioning_state: The provisioning state of the application.
    :vartype provisioning_state: str
    :param application_type: The application type.
    :type application_type: str
    :ivar application_state: The application state.
    :vartype application_state: str
    :param errors: The list of errors.
    :type errors: list[~azure.mgmt.hdinsight.models.Errors]
    :ivar created_date: The application create date time.
    :vartype created_date: str
    :ivar marketplace_identifier: The marketplace identifier.
    :vartype marketplace_identifier: str
    :param additional_properties: The additional properties for application.
    :type additional_properties: str
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'application_state': {'readonly': True},
        'created_date': {'readonly': True},
        'marketplace_identifier': {'readonly': True},
    }

    _attribute_map = {
        'compute_profile': {'key': 'computeProfile', 'type': 'ComputeProfile'},
        'install_script_actions': {'key': 'installScriptActions', 'type': '[RuntimeScriptAction]'},
        'uninstall_script_actions': {'key': 'uninstallScriptActions', 'type': '[RuntimeScriptAction]'},
        'https_endpoints': {'key': 'httpsEndpoints', 'type': '[ApplicationGetHttpsEndpoint]'},
        'ssh_endpoints': {'key': 'sshEndpoints', 'type': '[ApplicationGetEndpoint]'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'application_type': {'key': 'applicationType', 'type': 'str'},
        'application_state': {'key': 'applicationState', 'type': 'str'},
        'errors': {'key': 'errors', 'type': '[Errors]'},
        'created_date': {'key': 'createdDate', 'type': 'str'},
        'marketplace_identifier': {'key': 'marketplaceIdentifier', 'type': 'str'},
        'additional_properties': {'key': 'additionalProperties', 'type': 'str'},
    }

    def __init__(self, *, compute_profile=None, install_script_actions=None, uninstall_script_actions=None, https_endpoints=None, ssh_endpoints=None, application_type: str=None, errors=None, additional_properties: str=None, **kwargs) -> None:
        super(ApplicationProperties, self).__init__(**kwargs)
        self.compute_profile = compute_profile
        self.install_script_actions = install_script_actions
        self.uninstall_script_actions = uninstall_script_actions
        self.https_endpoints = https_endpoints
        self.ssh_endpoints = ssh_endpoints
        self.provisioning_state = None
        self.application_type = application_type
        self.application_state = None
        self.errors = errors
        self.created_date = None
        self.marketplace_identifier = None
        self.additional_properties = additional_properties
