# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .resource import Resource


class WorkerPool(Resource):
    """
    Worker pool of a hostingEnvironment (App Service Environment)

    :param id: Resource Id
    :type id: str
    :param name: Resource Name
    :type name: str
    :param kind: Kind of resource
    :type kind: str
    :param location: Resource Location
    :type location: str
    :param type: Resource type
    :type type: str
    :param tags: Resource tags
    :type tags: dict
    :param worker_size_id: Worker size id for referencing this worker pool
    :type worker_size_id: int
    :param compute_mode: Shared or dedicated web app hosting. Possible values
     include: 'Shared', 'Dedicated', 'Dynamic'
    :type compute_mode: str
    :param worker_size: VM size of the worker pool instances
    :type worker_size: str
    :param worker_count: Number of instances in the worker pool
    :type worker_count: int
    :param instance_names: Names of all instances in the worker pool (read
     only)
    :type instance_names: list of str
    :param sku:
    :type sku: :class:`SkuDescription
     <websitemanagementclient.models.SkuDescription>`
    """ 

    _validation = {
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'worker_size_id': {'key': 'properties.workerSizeId', 'type': 'int'},
        'compute_mode': {'key': 'properties.computeMode', 'type': 'ComputeModeOptions'},
        'worker_size': {'key': 'properties.workerSize', 'type': 'str'},
        'worker_count': {'key': 'properties.workerCount', 'type': 'int'},
        'instance_names': {'key': 'properties.instanceNames', 'type': '[str]'},
        'sku': {'key': 'sku', 'type': 'SkuDescription'},
    }

    def __init__(self, location, id=None, name=None, kind=None, type=None, tags=None, worker_size_id=None, compute_mode=None, worker_size=None, worker_count=None, instance_names=None, sku=None):
        super(WorkerPool, self).__init__(id=id, name=name, kind=kind, location=location, type=type, tags=tags)
        self.worker_size_id = worker_size_id
        self.compute_mode = compute_mode
        self.worker_size = worker_size
        self.worker_count = worker_count
        self.instance_names = instance_names
        self.sku = sku
