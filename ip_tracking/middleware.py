from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.http import HttpResponseForbidden
from django.core.cache import cache
from .models import RequestLog, BlockedIP
from .geolocation import geolocation_service
import logging

logger = logging.getLogger(__name__)

class IPLoggingMiddleware(MiddlewareMixin):
    def process_request(self, request):
        """
        Log the IP address, timestamp, path, and geolocation of every incoming request.
        Block requests from blacklisted IPs.
        """
        try:
            # Get the client IP address
            ip_address = self.get_client_ip(request)
            
            # Check if IP is blocked
            if self.is_ip_blocked(ip_address):
                logger.warning(f"Blocked request from IP: {ip_address}")
                return HttpResponseForbidden("Access forbidden: Your IP address has been blocked.")
            
            # Get the request path
            path = request.get_full_path()
            
            # Get geolocation data (cached for 24 hours)
            location_data = geolocation_service.get_location(ip_address)
            
            # Log the request with geolocation
            RequestLog.objects.create(
                ip_address=ip_address,
                timestamp=timezone.now(),
                path=path,
                country=location_data.get('country'),
                city=location_data.get('city')
            )
            
            # Log geolocation info for debugging
            if location_data.get('country') or location_data.get('city'):
                logger.info(f"Request from {ip_address} ({location_data.get('city', 'Unknown')}, {location_data.get('country', 'Unknown')})")
            
        except Exception as e:
            # Log the error but don't break the request
            logger.error(f"Error in IP logging middleware: {e}")
        
        return None
    
    def is_ip_blocked(self, ip_address):
        """
        Check if an IP address is in the blacklist.
        Uses caching for performance.
        """
        # Check cache first
        cache_key = f"blocked_ip_{ip_address}"
        cached_result = cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
        
        # Check database
        is_blocked = BlockedIP.objects.filter(ip_address=ip_address).exists()
        
        # Cache the result for 5 minutes
        cache.set(cache_key, is_blocked, 300)
        
        return is_blocked
    
    def get_client_ip(self, request):
        """
        Get the client's IP address from the request.
        Handles cases where the request comes through proxies.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip