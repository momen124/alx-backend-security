from django.core.management.base import BaseCommand, CommandError
from django.core.validators import validate_ipv46_address
from django.core.exceptions import ValidationError
from django.core.cache import cache
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = 'Unblock an IP address by removing it from the blacklist'

    def add_arguments(self, parser):
        parser.add_argument(
            'ip_address',
            type=str,
            help='IP address to unblock'
        )

    def handle(self, *args, **options):
        ip_address = options['ip_address']

        # Validate IP address
        try:
            validate_ipv46_address(ip_address)
        except ValidationError:
            raise CommandError(f'Invalid IP address: {ip_address}')

        # Check if IP is blocked
        try:
            blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
            blocked_ip.delete()
            
            # Clear cache for this IP
            cache_key = f"blocked_ip_{ip_address}"
            cache.delete(cache_key)
            
            self.stdout.write(
                self.style.SUCCESS(f'Successfully unblocked IP address: {ip_address}')
            )
        except BlockedIP.DoesNotExist:
            self.stdout.write(
                self.style.WARNING(f'IP address {ip_address} is not blocked.')
            )