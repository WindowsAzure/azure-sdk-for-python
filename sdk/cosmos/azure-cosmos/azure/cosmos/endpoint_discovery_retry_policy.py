#The MIT License (MIT)
#Copyright (c) 2014 Microsoft Corporation

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

"""Internal class for endpoint discovery retry policy implementation in the Azure Cosmos database service.
"""

import logging
import logging.config
from azure.cosmos.documents import _OperationType

class _EndpointDiscoveryRetryPolicy(object):
    """The endpoint discovery retry policy class used for geo-replicated database accounts
       to handle the write forbidden exceptions due to writable/readable location changes
       (say, after a failover).
    """

    Max_retry_attempt_count = 120
    Retry_after_in_milliseconds = 1000

    def __init__(self, connection_policy, global_endpoint_manager, *args):
        self.global_endpoint_manager = global_endpoint_manager
        self._max_retry_attempt_count = _EndpointDiscoveryRetryPolicy.Max_retry_attempt_count
        self.failover_retry_count = 0
        self.retry_after_in_milliseconds = _EndpointDiscoveryRetryPolicy.Retry_after_in_milliseconds
        self.connection_policy = connection_policy
        self.request = args[0] if args else None
        #clear previous location-based routing directive
        if (self.request):
            self.request.clear_route_to_location()

            # Resolve the endpoint for the request and pin the resolution to the resolved endpoint
            # This enables marking the endpoint unavailability on endpoint failover/unreachability
            self.location_endpoint = self.global_endpoint_manager.resolve_service_endpoint(self.request)
            self.request.route_to_location(self.location_endpoint)
        self.logger = logging.getLogger(__name__)

    def ShouldRetry(self, exception):
        """Returns true if should retry based on the passed-in exception.

        :param (errors.HTTPFailure instance) exception: 

        :rtype:
            boolean

        """
        if not self.connection_policy.EnableEndpointDiscovery:
            self.logger.debug('Not retrying again.')
            return False

        if self.failover_retry_count >= self.Max_retry_attempt_count:
            self.logger.debug('Not retrying again.')
            return False

        self.failover_retry_count += 1

        if self.location_endpoint:
            if _OperationType.IsReadOnlyOperation(self.request.operation_type):
                #Mark current read endpoint as unavailable
                self.global_endpoint_manager.mark_endpoint_unavailable_for_read(self.location_endpoint)
            else:
                self.global_endpoint_manager.mark_endpoint_unavailable_for_write(self.location_endpoint)

        # set the refresh_needed flag to ensure that endpoint list is
        # refreshed with new writable and readable locations
        self.global_endpoint_manager.refresh_needed = True
        
        # clear previous location-based routing directive
        self.request.clear_route_to_location()

        # set location-based routing directive based on retry count
        # simulating single master writes by ensuring usePreferredLocations
        # is set to false
        self.request.route_to_location_with_preferred_location_flag(self.failover_retry_count, False)
        
        # Resolve the endpoint for the request and pin the resolution to the resolved endpoint
        # This enables marking the endpoint unavailability on endpoint failover/unreachability
        self.location_endpoint = self.global_endpoint_manager.resolve_service_endpoint(self.request)
        self.request.route_to_location(self.location_endpoint)
        self.logger.debug('Retrying again.')
        return True
