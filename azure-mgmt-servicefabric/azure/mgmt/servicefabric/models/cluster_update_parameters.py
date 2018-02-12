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

    :param reliability_level: The reliability level sets the replica set size
     of system services. Learn about
     [ReliabilityLevel](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-cluster-capacity).
     Possible values include: 'Bronze', 'Silver', 'Gold'
    :type reliability_level: str or ~azure.mgmt.servicefabric.models.enum
    :param upgrade_mode: The upgrade mode of the cluster. This indicates if
     the cluster should be automatically upgraded when new Service Fabric
     runtime version is available. Possible values include: 'Automatic',
     'Manual'
    :type upgrade_mode: str or ~azure.mgmt.servicefabric.models.enum
    :param cluster_code_version: The Service Fabric runtime version of the
     cluster. This property can only by set the user when **upgradeMode** is
     set to 'Manual'. To get list of available Service Fabric versions for new
     clusters use [ClusterVersion API](./ClusterVersion.md). To get the list of
     available version for existing clusters use **availableClusterVersions**.
    :type cluster_code_version: str
    :param certificate: The certificate to use for securing the cluster. The
     certificate provided will be used for  node to node security within the
     cluster, SSL certificate for cluster management endpoint and default
     admin client.
    :type certificate: ~azure.mgmt.servicefabric.models.CertificateDescription
    :param client_certificate_thumbprints: The list of client certificates
     referenced by thumbprint that are allowed to manage the cluster. This will
     overwrite the existing list.
    :type client_certificate_thumbprints:
     list[~azure.mgmt.servicefabric.models.ClientCertificateThumbprint]
    :param client_certificate_common_names: The list of client certificates
     referenced by common name that are allowed to manage the cluster. This
     will overwrite the existing list.
    :type client_certificate_common_names:
     list[~azure.mgmt.servicefabric.models.ClientCertificateCommonName]
    :param fabric_settings: The list of custom fabric settings to configure
     the cluster. This will overwrite the existing list.
    :type fabric_settings:
     list[~azure.mgmt.servicefabric.models.SettingsSectionDescription]
    :param reverse_proxy_certificate: The server certificate used by reverse
     proxy.
    :type reverse_proxy_certificate:
     ~azure.mgmt.servicefabric.models.CertificateDescription
    :param node_types: The list of node types in the cluster. This will
     overwrite the existing list.
    :type node_types:
     list[~azure.mgmt.servicefabric.models.NodeTypeDescription]
    :param upgrade_description: The policy to use when upgrading the cluster.
    :type upgrade_description:
     ~azure.mgmt.servicefabric.models.ClusterUpgradePolicy
    :param add_on_features: The list of add-on features to enable in the
     cluster.
    :type add_on_features: list[str]
    :param tags: Cluster update parameters
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'reliability_level': {'key': 'properties.reliabilityLevel', 'type': 'str'},
        'upgrade_mode': {'key': 'properties.upgradeMode', 'type': 'str'},
        'cluster_code_version': {'key': 'properties.clusterCodeVersion', 'type': 'str'},
        'certificate': {'key': 'properties.certificate', 'type': 'CertificateDescription'},
        'client_certificate_thumbprints': {'key': 'properties.clientCertificateThumbprints', 'type': '[ClientCertificateThumbprint]'},
        'client_certificate_common_names': {'key': 'properties.clientCertificateCommonNames', 'type': '[ClientCertificateCommonName]'},
        'fabric_settings': {'key': 'properties.fabricSettings', 'type': '[SettingsSectionDescription]'},
        'reverse_proxy_certificate': {'key': 'properties.reverseProxyCertificate', 'type': 'CertificateDescription'},
        'node_types': {'key': 'properties.nodeTypes', 'type': '[NodeTypeDescription]'},
        'upgrade_description': {'key': 'properties.upgradeDescription', 'type': 'ClusterUpgradePolicy'},
        'add_on_features': {'key': 'properties.addOnFeatures', 'type': '[str]'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, reliability_level=None, upgrade_mode=None, cluster_code_version=None, certificate=None, client_certificate_thumbprints=None, client_certificate_common_names=None, fabric_settings=None, reverse_proxy_certificate=None, node_types=None, upgrade_description=None, add_on_features=None, tags=None):
        super(ClusterUpdateParameters, self).__init__()
        self.reliability_level = reliability_level
        self.upgrade_mode = upgrade_mode
        self.cluster_code_version = cluster_code_version
        self.certificate = certificate
        self.client_certificate_thumbprints = client_certificate_thumbprints
        self.client_certificate_common_names = client_certificate_common_names
        self.fabric_settings = fabric_settings
        self.reverse_proxy_certificate = reverse_proxy_certificate
        self.node_types = node_types
        self.upgrade_description = upgrade_description
        self.add_on_features = add_on_features
        self.tags = tags
