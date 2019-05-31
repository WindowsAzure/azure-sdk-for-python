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


class ClusterUpdateParameters(Model):
    """Cluster update request.

    :param add_on_features: The list of add-on features to enable in the
     cluster.
    :type add_on_features: list[str]
    :param certificate: The certificate to use for securing the cluster. The
     certificate provided will be used for  node to node security within the
     cluster, SSL certificate for cluster management endpoint and default
     admin client.
    :type certificate: ~azure.mgmt.servicefabric.models.CertificateDescription
    :param certificate_common_names: Describes a list of server certificates
     referenced by common name that are used to secure the cluster.
    :type certificate_common_names:
     ~azure.mgmt.servicefabric.models.ServerCertificateCommonNames
    :param client_certificate_common_names: The list of client certificates
     referenced by common name that are allowed to manage the cluster. This
     will overwrite the existing list.
    :type client_certificate_common_names:
     list[~azure.mgmt.servicefabric.models.ClientCertificateCommonName]
    :param client_certificate_thumbprints: The list of client certificates
     referenced by thumbprint that are allowed to manage the cluster. This will
     overwrite the existing list.
    :type client_certificate_thumbprints:
     list[~azure.mgmt.servicefabric.models.ClientCertificateThumbprint]
    :param cluster_code_version: The Service Fabric runtime version of the
     cluster. This property can only by set the user when **upgradeMode** is
     set to 'Manual'. To get list of available Service Fabric versions for new
     clusters use [ClusterVersion API](./ClusterVersion.md). To get the list of
     available version for existing clusters use **availableClusterVersions**.
    :type cluster_code_version: str
    :param event_store_service_enabled: Indicates if the event store service
     is enabled.
    :type event_store_service_enabled: bool
    :param fabric_settings: The list of custom fabric settings to configure
     the cluster. This will overwrite the existing list.
    :type fabric_settings:
     list[~azure.mgmt.servicefabric.models.SettingsSectionDescription]
    :param node_types: The list of node types in the cluster. This will
     overwrite the existing list.
    :type node_types:
     list[~azure.mgmt.servicefabric.models.NodeTypeDescription]
    :param reliability_level: The reliability level sets the replica set size
     of system services. Learn about
     [ReliabilityLevel](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-cluster-capacity).
     - None - Run the System services with a target replica set count of 1.
     This should only be used for test clusters.
     - Bronze - Run the System services with a target replica set count of 3.
     This should only be used for test clusters.
     - Silver - Run the System services with a target replica set count of 5.
     - Gold - Run the System services with a target replica set count of 7.
     - Platinum - Run the System services with a target replica set count of 9.
     . Possible values include: 'None', 'Bronze', 'Silver', 'Gold', 'Platinum'
    :type reliability_level: str or ~azure.mgmt.servicefabric.models.enum
    :param reverse_proxy_certificate: The server certificate used by reverse
     proxy.
    :type reverse_proxy_certificate:
     ~azure.mgmt.servicefabric.models.CertificateDescription
    :param upgrade_description: The policy to use when upgrading the cluster.
    :type upgrade_description:
     ~azure.mgmt.servicefabric.models.ClusterUpgradePolicy
    :param upgrade_mode: The upgrade mode of the cluster when new Service
     Fabric runtime version is available.
     - Automatic - The cluster will be automatically upgraded to the latest
     Service Fabric runtime version as soon as it is available.
     - Manual - The cluster will not be automatically upgraded to the latest
     Service Fabric runtime version. The cluster is upgraded by setting the
     **clusterCodeVersion** property in the cluster resource.
     . Possible values include: 'Automatic', 'Manual'
    :type upgrade_mode: str or ~azure.mgmt.servicefabric.models.enum
    :param tags: Cluster update parameters
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'add_on_features': {'key': 'properties.addOnFeatures', 'type': '[str]'},
        'certificate': {'key': 'properties.certificate', 'type': 'CertificateDescription'},
        'certificate_common_names': {'key': 'properties.certificateCommonNames', 'type': 'ServerCertificateCommonNames'},
        'client_certificate_common_names': {'key': 'properties.clientCertificateCommonNames', 'type': '[ClientCertificateCommonName]'},
        'client_certificate_thumbprints': {'key': 'properties.clientCertificateThumbprints', 'type': '[ClientCertificateThumbprint]'},
        'cluster_code_version': {'key': 'properties.clusterCodeVersion', 'type': 'str'},
        'event_store_service_enabled': {'key': 'properties.eventStoreServiceEnabled', 'type': 'bool'},
        'fabric_settings': {'key': 'properties.fabricSettings', 'type': '[SettingsSectionDescription]'},
        'node_types': {'key': 'properties.nodeTypes', 'type': '[NodeTypeDescription]'},
        'reliability_level': {'key': 'properties.reliabilityLevel', 'type': 'str'},
        'reverse_proxy_certificate': {'key': 'properties.reverseProxyCertificate', 'type': 'CertificateDescription'},
        'upgrade_description': {'key': 'properties.upgradeDescription', 'type': 'ClusterUpgradePolicy'},
        'upgrade_mode': {'key': 'properties.upgradeMode', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(ClusterUpdateParameters, self).__init__(**kwargs)
        self.add_on_features = kwargs.get('add_on_features', None)
        self.certificate = kwargs.get('certificate', None)
        self.certificate_common_names = kwargs.get('certificate_common_names', None)
        self.client_certificate_common_names = kwargs.get('client_certificate_common_names', None)
        self.client_certificate_thumbprints = kwargs.get('client_certificate_thumbprints', None)
        self.cluster_code_version = kwargs.get('cluster_code_version', None)
        self.event_store_service_enabled = kwargs.get('event_store_service_enabled', None)
        self.fabric_settings = kwargs.get('fabric_settings', None)
        self.node_types = kwargs.get('node_types', None)
        self.reliability_level = kwargs.get('reliability_level', None)
        self.reverse_proxy_certificate = kwargs.get('reverse_proxy_certificate', None)
        self.upgrade_description = kwargs.get('upgrade_description', None)
        self.upgrade_mode = kwargs.get('upgrade_mode', None)
        self.tags = kwargs.get('tags', None)
