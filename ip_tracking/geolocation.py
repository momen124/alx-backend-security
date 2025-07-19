import requests
import logging
from django.conf import settings
from django.core.cache import cache
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class GeolocationService:
    """
    Service for getting geolocation data from IP addresses
    """
    
    def __init__(self):
        self.api_url = getattr(settings, 'GEOLOCATION_API_URL', 'http://ip-api.com/json/')
        self.api_key = getattr(settings, 'GEOLOCATION_API_KEY', None)
        self.cache_timeout = 24 * 60 * 60  # 24 hours in seconds
    
    def get_location(self, ip_address: str) -> Dict[str, Optional[str]]:
        """
        Get geolocation data for an IP address with caching
        """
        # Skip private/local IPs
        if self._is_private_ip(ip_address):
            return {'country': None, 'city': None}
        
        # Check cache first
        cache_key = f"geolocation_{ip_address}"
        cached_data = cache.get(cache_key)
        
        if cached_data is not None:
            return cached_data
        
        # Fetch from API
        location_data = self._fetch_from_api(ip_address)
        
        # Cache the result for 24 hours
        cache.set(cache_key, location_data, self.cache_timeout)
        
        return location_data
    
    def _fetch_from_api(self, ip_address: str) -> Dict[str, Optional[str]]:
        """
        Fetch geolocation data from external API
        """
        try:
            # Different API formats
            if 'ip-api.com' in self.api_url:
                response = self._fetch_from_ipapi(ip_address)
            elif 'ipapi.co' in self.api_url:
                response = self._fetch_from_ipapi_co(ip_address)
            elif 'ipinfo.io' in self.api_url:
                response = self._fetch_from_ipinfo(ip_address)
            else:
                response = self._fetch_generic(ip_address)
            
            return response
            
        except Exception as e:
            logger.error(f"Error fetching geolocation for {ip_address}: {e}")
            return {'country': None, 'city': None}
    
    def _fetch_from_ipapi(self, ip_address: str) -> Dict[str, Optional[str]]:
        """
        Fetch from ip-api.com (free, no key required)
        """
        url = f"http://ip-api.com/json/{ip_address}"
        
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get('status') == 'success':
            return {
                'country': data.get('country'),
                'city': data.get('city')
            }
        else:
            logger.warning(f"IP-API returned error for {ip_address}: {data.get('message')}")
            return {'country': None, 'city': None}
    
    def _fetch_from_ipapi_co(self, ip_address: str) -> Dict[str, Optional[str]]:
        """
        Fetch from ipapi.co
        """
        url = f"https://ipapi.co/{ip_address}/json/"
        
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        
        data = response.json()
        
        if 'error' not in data:
            return {
                'country': data.get('country_name'),
                'city': data.get('city')
            }
        else:
            logger.warning(f"IPAPI.co returned error for {ip_address}: {data.get('reason')}")
            return {'country': None, 'city': None}
    
    def _fetch_from_ipinfo(self, ip_address: str) -> Dict[str, Optional[str]]:
        """
        Fetch from ipinfo.io
        """
        url = f"https://ipinfo.io/{ip_address}/json"
        
        headers = {}
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        
        data = response.json()
        
        return {
            'country': data.get('country'),
            'city': data.get('city')
        }
    
    def _fetch_generic(self, ip_address: str) -> Dict[str, Optional[str]]:
        """
        Generic fetch method
        """
        url = self.api_url.format(ip=ip_address)
        
        headers = {}
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        
        data = response.json()
        
        return {
            'country': data.get('country'),
            'city': data.get('city')
        }
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """
        Check if IP address is private/local
        """
        private_ranges = [
            '127.',      # localhost
            '10.',       # Private network
            '192.168.',  # Private network
            '172.16.',   # Private network (172.16.0.0 to 172.31.255.255)
            '::1',       # IPv6 localhost
            'fc00:',     # IPv6 private
            'fe80:',     # IPv6 link-local
        ]
        
        return any(ip_address.startswith(prefix) for prefix in private_ranges) or \
               any(ip_address.startswith(f'172.{i}.') for i in range(16, 32))

# Create a singleton instance
geolocation_service = GeolocationService()