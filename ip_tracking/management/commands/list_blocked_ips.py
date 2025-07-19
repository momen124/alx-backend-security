from django.core.management.base import BaseCommand
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = 'List all blocked IP addresses'

    def handle(self, *args, **options):
        blocked_ips = BlockedIP.objects.all()
        
        if not blocked_ips.exists():
            self.stdout.write(
                self.style.WARNING('No IP addresses are currently blocked.')
            )
            return

        self.stdout.write(
            self.style.SUCCESS(f'Found {blocked_ips.count()} blocked IP addresses:')
        )
        self.stdout.write('')
        
        for blocked_ip in blocked_ips:
            self.stdout.write(f'IP: {blocked_ip.ip_address}')
            self.stdout.write(f'Blocked on: {blocked_ip.created_at}')
            if blocked_ip.reason:
                self.stdout.write(f'Reason: {blocked_ip.reason}')
            self.stdout.write('-' * 40)