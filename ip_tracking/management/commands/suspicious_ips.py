from django.core.management.base import BaseCommand
from ip_tracking.models import SuspiciousIP

class Command(BaseCommand):
    help = 'List suspicious IP addresses'

    def add_arguments(self, parser):
        parser.add_argument(
            '--severity',
            type=str,
            choices=['low', 'medium', 'high'],
            help='Filter by severity level'
        )
        parser.add_argument(
            '--unresolved-only',
            action='store_true',
            help='Show only unresolved suspicious activities'
        )

    def handle(self, *args, **options):
        queryset = SuspiciousIP.objects.all()
        
        if options['severity']:
            queryset = queryset.filter(severity=options['severity'])
        
        if options['unresolved_only']:
            queryset = queryset.filter(is_resolved=False)
        
        if not queryset.exists():
            self.stdout.write(
                self.style.WARNING('No suspicious IP addresses found.')
            )
            return
        
        self.stdout.write(
            self.style.SUCCESS(f'Found {queryset.count()} suspicious IP addresses:')
        )
        self.stdout.write('')
        
        for suspicious_ip in queryset:
            status = "Resolved" if suspicious_ip.is_resolved else "Active"
            self.stdout.write(f'IP: {suspicious_ip.ip_address}')
            self.stdout.write(f'Reason: {suspicious_ip.get_reason_display()}')
            self.stdout.write(f'Severity: {suspicious_ip.severity.upper()}')
            self.stdout.write(f'Details: {suspicious_ip.details}')
            self.stdout.write(f'Status: {status}')
            self.stdout.write(f'Last seen: {suspicious_ip.last_seen}')
            self.stdout.write('-' * 50)