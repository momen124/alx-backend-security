from django.core.management.base import BaseCommand
from ip_tracking.tasks import detect_anomalies

class Command(BaseCommand):
    help = 'Run anomaly detection manually'

    def handle(self, *args, **options):
        self.stdout.write('Running anomaly detection...')
        
        result = detect_anomalies.delay()
        
        # Wait for the task to complete
        task_result = result.get()
        
        self.stdout.write(
            self.style.SUCCESS(f'Anomaly detection completed: {task_result}')
        )