from django.core.management.base import BaseCommand
from django.db.models import Count
from ip_tracking.models import RequestLog

class Command(BaseCommand):
    help = 'Display geolocation statistics from request logs'

    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            default=10,
            help='Number of top results to show'
        )
        parser.add_argument(
            '--by-country',
            action='store_true',
            help='Show statistics by country'
        )
        parser.add_argument(
            '--by-city',
            action='store_true',
            help='Show statistics by city'
        )

    def handle(self, *args, **options):
        limit = options['limit']
        
        if options['by_country']:
            self.show_country_stats(limit)
        elif options['by_city']:
            self.show_city_stats(limit)
        else:
            self.show_all_stats(limit)

    def show_country_stats(self, limit):
        """Show request statistics by country"""
        self.stdout.write(self.style.SUCCESS(f'Top {limit} countries by request count:'))
        self.stdout.write('')
        
        stats = RequestLog.objects.values('country').annotate(
            count=Count('id')
        ).filter(
            country__isnull=False
        ).order_by('-count')[:limit]
        
        for stat in stats:
            self.stdout.write(f"{stat['country']}: {stat['count']} requests")

    def show_city_stats(self, limit):
        """Show request statistics by city"""
        self.stdout.write(self.style.SUCCESS(f'Top {limit} cities by request count:'))
        self.stdout.write('')
        
        stats = RequestLog.objects.values('city', 'country').annotate(
            count=Count('id')
        ).filter(
            city__isnull=False
        ).order_by('-count')[:limit]
        
        for stat in stats:
            location = f"{stat['city']}, {stat['country']}" if stat['country'] else stat['city']
            self.stdout.write(f"{location}: {stat['count']} requests")

    def show_all_stats(self, limit):
        """Show both country and city statistics"""
        self.show_country_stats(limit)
        self.stdout.write('')
        self.show_city_stats(limit)