from django.core.management.base import BaseCommand, CommandError
from django.core.validators import validate_ipv46_address
from django.core.exceptions import ValidationError
from django.core.cache import cache
from ip_tracking.models import BlockedIP
import sys

class Command(BaseCommand):
    help = 'Block an IP address by adding it to the blacklist'

    def add_arguments(self, parser):
        parser.add_argument(
            'ip_address',
            type=str,
            help='IP address to block'
        )
        parser.add_argument(
            '--reason',
            type=str,
            help='Reason for blocking the IP address',
            default=''
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force block even if IP is already blocked'
        )

    def handle(self, *args, **options):
        ip_address = options['ip_address']
        reason = options['reason']
        force = options['force']

        # Validate IP address
        try:
            validate_ipv46_address(ip_address)
        except ValidationError:
            raise CommandError(f'Invalid IP address: {ip_address}')

        # Check if IP is already blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            if not force:
                self.stdout.write(
                    self.style.WARNING(f'IP address {ip_address} is already blocked.')
                )
                return
            else:
                self.stdout.write(
                    self.style.WARNING(f'IP address {ip_address} is already blocked, but forcing update...')
                )
                # Update the existing record
                blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
                blocked_ip.reason = reason
                blocked_ip.save()
        else:
            # Create new blocked IP record
            blocked_ip = BlockedIP.objects.create(
                ip_address=ip_address,
                reason=reason
            )

        # Clear cache for this IP
        cache_key = f"blocked_ip_{ip_address}"
        cache.delete(cache_key)

        self.stdout.write(
            self.style.SUCCESS(f'Successfully blocked IP address: {ip_address}')
        )
        if reason:
            self.stdout.write(f'Reason: {reason}')