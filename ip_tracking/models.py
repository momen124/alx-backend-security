from django.db import models
from django.utils import timezone

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        db_table = 'ip_tracking_requestlog'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['path']),
        ]
    
    def __str__(self):
        location = f"{self.city}, {self.country}" if self.city and self.country else "Unknown"
        return f"{self.ip_address} ({location}) - {self.path} - {self.timestamp}"

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    reason = models.CharField(max_length=255, blank=True, null=True)
    
    class Meta:
        db_table = 'ip_tracking_blockedip'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Blocked IP: {self.ip_address}"

class SuspiciousIP(models.Model):
    REASON_CHOICES = [
        ('high_volume', 'High Request Volume'),
        ('sensitive_paths', 'Accessing Sensitive Paths'),
        ('rapid_requests', 'Rapid Sequential Requests'),
        ('unusual_patterns', 'Unusual Access Patterns'),
        ('failed_logins', 'Multiple Failed Login Attempts'),
    ]
    
    ip_address = models.GenericIPAddressField()
    reason = models.CharField(max_length=50, choices=REASON_CHOICES)
    details = models.TextField(blank=True, null=True)  # Additional details about the anomaly
    request_count = models.IntegerField(default=0)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    severity = models.CharField(
        max_length=10,
        choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')],
        default='medium'
    )
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        db_table = 'ip_tracking_suspiciousip'
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['ip_address', 'is_resolved']),
            models.Index(fields=['reason', 'severity']),
            models.Index(fields=['last_seen']),
        ]
        unique_together = ['ip_address', 'reason']  # Prevent duplicate entries for same IP and reason
    
    def __str__(self):
        return f"Suspicious IP: {self.ip_address} - {self.get_reason_display()}"
    
    def resolve(self):
        """Mark the suspicious activity as resolved"""
        self.is_resolved = True
        self.resolved_at = timezone.now()
        self.save()