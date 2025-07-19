from celery import shared_task
from django.utils import timezone
from django.conf import settings
from django.db.models import Count, Q
from datetime import timedelta
import logging
from .models import RequestLog, SuspiciousIP, BlockedIP

logger = logging.getLogger(__name__)

@shared_task
def detect_anomalies():
    """
    Main anomaly detection task that runs hourly to identify suspicious IPs.
    """
    logger.info("Starting anomaly detection task")
    
    try:
        # Get detection settings
        detection_settings = getattr(settings, 'ANOMALY_DETECTION', {})
        request_threshold = detection_settings.get('REQUEST_THRESHOLD_PER_HOUR', 100)
        sensitive_paths = detection_settings.get('SENSITIVE_PATHS', ['/admin', '/login'])
        rapid_threshold = detection_settings.get('RAPID_REQUEST_THRESHOLD', 20)
        failed_login_threshold = detection_settings.get('FAILED_LOGIN_THRESHOLD', 10)
        
        # Define time windows
        one_hour_ago = timezone.now() - timedelta(hours=1)
        one_minute_ago = timezone.now() - timedelta(minutes=1)
        
        # Run different anomaly detection algorithms
        high_volume_ips = detect_high_volume_requests(one_hour_ago, request_threshold)
        sensitive_path_ips = detect_sensitive_path_access(one_hour_ago, sensitive_paths)
        rapid_request_ips = detect_rapid_requests(one_minute_ago, rapid_threshold)
        failed_login_ips = detect_failed_logins(one_hour_ago, failed_login_threshold)
        
        # Process and log results
        total_flagged = (len(high_volume_ips) + len(sensitive_path_ips) + 
                        len(rapid_request_ips) + len(failed_login_ips))
        
        logger.info(f"Anomaly detection completed. Flagged {total_flagged} suspicious activities")
        
        return {
            'high_volume': len(high_volume_ips),
            'sensitive_paths': len(sensitive_path_ips),
            'rapid_requests': len(rapid_request_ips),
            'failed_logins': len(failed_login_ips),
            'total_flagged': total_flagged
        }
        
    except Exception as e:
        logger.error(f"Error in anomaly detection: {e}")
        raise

def detect_high_volume_requests(since_time, threshold):
    """
    Detect IPs with unusually high request volumes.
    """
    logger.info(f"Detecting high volume requests (threshold: {threshold} requests/hour)")
    
    high_volume_ips = RequestLog.objects.filter(
        timestamp__gte=since_time
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(
        request_count__gte=threshold
    )
    
    flagged_ips = []
    for ip_data in high_volume_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        # Determine severity based on request count
        if request_count > threshold * 3:
            severity = 'high'
        elif request_count > threshold * 2:
            severity = 'medium'
        else:
            severity = 'low'
        
        suspicious_ip, created = SuspiciousIP.objects.get_or_create(
            ip_address=ip_address,
            reason='high_volume',
            defaults={
                'details': f'Made {request_count} requests in the last hour',
                'request_count': request_count,
                'severity': severity,
            }
        )
        
        if not created:
            # Update existing record
            suspicious_ip.request_count = request_count
            suspicious_ip.last_seen = timezone.now()
            suspicious_ip.details = f'Made {request_count} requests in the last hour'
            suspicious_ip.severity = severity
            suspicious_ip.save()
        
        flagged_ips.append(ip_address)
        logger.warning(f"High volume detected: {ip_address} made {request_count} requests")
    
    return flagged_ips

def detect_sensitive_path_access(since_time, sensitive_paths):
    """
    Detect IPs accessing sensitive paths frequently.
    """
    logger.info(f"Detecting sensitive path access for paths: {sensitive_paths}")
    
    # Create Q objects for path matching
    path_filters = Q()
    for path in sensitive_paths:
        path_filters |= Q(path__icontains=path)
    
    sensitive_access_ips = RequestLog.objects.filter(
        timestamp__gte=since_time
    ).filter(path_filters).values('ip_address').annotate(
        access_count=Count('id')
    ).filter(
        access_count__gte=5  # 5 or more accesses to sensitive paths
    )
    
    flagged_ips = []
    for ip_data in sensitive_access_ips:
        ip_address = ip_data['ip_address']
        access_count = ip_data['access_count']
        
        # Get the specific paths accessed
        accessed_paths = RequestLog.objects.filter(
            ip_address=ip_address,
            timestamp__gte=since_time
        ).filter(path_filters).values_list('path', flat=True).distinct()
        
        severity = 'high' if access_count > 10 else 'medium'
        
        suspicious_ip, created = SuspiciousIP.objects.get_or_create(
            ip_address=ip_address,
            reason='sensitive_paths',
            defaults={
                'details': f'Accessed sensitive paths {access_count} times: {list(accessed_paths)}',
                'request_count': access_count,
                'severity': severity,
            }
        )
        
        if not created:
            suspicious_ip.request_count = access_count
            suspicious_ip.last_seen = timezone.now()
            suspicious_ip.details = f'Accessed sensitive paths {access_count} times: {list(accessed_paths)}'
            suspicious_ip.severity = severity
            suspicious_ip.save()
        
        flagged_ips.append(ip_address)
        logger.warning(f"Sensitive path access: {ip_address} accessed {list(accessed_paths)} {access_count} times")
    
    return flagged_ips

def detect_rapid_requests(since_time, threshold):
    """
    Detect IPs making rapid sequential requests (potential bot behavior).
    """
    logger.info(f"Detecting rapid requests (threshold: {threshold} requests/minute)")
    
    rapid_request_ips = RequestLog.objects.filter(
        timestamp__gte=since_time
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(
        request_count__gte=threshold
    )
    
    flagged_ips = []
    for ip_data in rapid_request_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        severity = 'high' if request_count > threshold * 2 else 'medium'
        
        suspicious_ip, created = SuspiciousIP.objects.get_or_create(
            ip_address=ip_address,
            reason='rapid_requests',
            defaults={
                'details': f'Made {request_count} requests in the last minute',
                'request_count': request_count,
                'severity': severity,
            }
        )
        
        if not created:
            suspicious_ip.request_count = request_count
            suspicious_ip.last_seen = timezone.now()
            suspicious_ip.details = f'Made {request_count} requests in the last minute'
            suspicious_ip.severity = severity
            suspicious_ip.save()
        
        flagged_ips.append(ip_address)
        logger.warning(f"Rapid requests detected: {ip_address} made {request_count} requests in 1 minute")
    
    return flagged_ips

def detect_failed_logins(since_time, threshold):
    """
    Detect IPs with multiple failed login attempts.
    """
    logger.info(f"Detecting failed login attempts (threshold: {threshold} failures/hour)")
    
    login_paths = ['/login', '/api/login', '/admin/login']
    path_filters = Q()
    for path in login_paths:
        path_filters |= Q(path__icontains=path)
    
    # This is a simplified approach - in a real application, you'd want to track
    # actual failed login attempts more precisely
    failed_login_ips = RequestLog.objects.filter(
        timestamp__gte=since_time
    ).filter(path_filters).values('ip_address').annotate(
        attempt_count=Count('id')
    ).filter(
        attempt_count__gte=threshold
    )
    
    flagged_ips = []
    for ip_data in failed_login_ips:
        ip_address = ip_data['ip_address']
        attempt_count = ip_data['attempt_count']
        
        severity = 'high' if attempt_count > threshold * 2 else 'medium'
        
        suspicious_ip, created = SuspiciousIP.objects.get_or_create(
            ip_address=ip_address,
            reason='failed_logins',
            defaults={
                'details': f'Made {attempt_count} login attempts in the last hour',
                'request_count': attempt_count,
                'severity': severity,
            }
        )
        
        if not created:
            suspicious_ip.request_count = attempt_count
            suspicious_ip.last_seen = timezone.now()
            suspicious_ip.details = f'Made {attempt_count} login attempts in the last hour'
            suspicious_ip.severity = severity
            suspicious_ip.save()
        
        flagged_ips.append(ip_address)
        logger.warning(f"Multiple login attempts: {ip_address} made {attempt_count} attempts")
    
    return flagged_ips

@shared_task
def cleanup_old_logs():
    """
    Clean up old request logs to prevent database bloat.
    """
    logger.info("Starting log cleanup task")
    
    try:
        retention_days = getattr(settings, 'ANOMALY_DETECTION', {}).get('LOG_RETENTION_DAYS', 30)
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        
        # Delete old request logs
        deleted_logs, _ = RequestLog.objects.filter(timestamp__lt=cutoff_date).delete()
        
        # Mark old suspicious IPs as resolved if they haven't been active
        old_suspicious = SuspiciousIP.objects.filter(
            last_seen__lt=cutoff_date,
            is_resolved=False
        )
        
        resolved_count = 0
        for suspicious_ip in old_suspicious:
            suspicious_ip.resolve()
            resolved_count += 1
        
        logger.info(f"Cleanup completed: deleted {deleted_logs} old logs, resolved {resolved_count} old suspicious IPs")
        
        return {
            'deleted_logs': deleted_logs,
            'resolved_suspicious': resolved_count
        }
        
    except Exception as e:
        logger.error(f"Error in log cleanup: {e}")
        raise

@shared_task
def auto_block_suspicious_ips():
    """
    Automatically block IPs with high-severity suspicious activity.
    """
    logger.info("Starting auto-block task for suspicious IPs")
    
    try:
        # Get high-severity unresolved suspicious IPs
        high_risk_ips = SuspiciousIP.objects.filter(
            severity='high',
            is_resolved=False
        ).values('ip_address').distinct()
        
        blocked_count = 0
        for ip_data in high_risk_ips:
            ip_address = ip_data['ip_address']
            
            # Check if already blocked
            if not BlockedIP.objects.filter(ip_address=ip_address).exists():
                # Get reasons for blocking
                reasons = SuspiciousIP.objects.filter(
                    ip_address=ip_address,
                    severity='high',
                    is_resolved=False
                ).values_list('reason', flat=True)
                
                reason_text = f"Auto-blocked due to suspicious activity: {', '.join(reasons)}"
                
                BlockedIP.objects.create(
                    ip_address=ip_address,
                    reason=reason_text
                )
                
                # Mark suspicious activities as resolved
                SuspiciousIP.objects.filter(
                    ip_address=ip_address,
                    is_resolved=False
                ).update(is_resolved=True, resolved_at=timezone.now())
                
                blocked_count += 1
                logger.warning(f"Auto-blocked IP: {ip_address} - {reason_text}")
        
        logger.info(f"Auto-block completed: blocked {blocked_count} IPs")
        
        return {'blocked_count': blocked_count}
        
    except Exception as e:
        logger.error(f"Error in auto-block task: {e}")
        raise