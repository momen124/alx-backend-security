from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.contrib import messages
from django.conf import settings
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from .models import RequestLog, BlockedIP
import logging

logger = logging.getLogger(__name__)

def get_rate_limit_key(group, request):
    """
    Custom key function for rate limiting.
    Returns different keys for authenticated vs anonymous users.
    """
    if request.user.is_authenticated:
        return f"user:{request.user.id}"
    else:
        # Get IP address (same logic as in middleware)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return f"ip:{ip}"

def get_rate_limit_rate(group, request):
    """
    Custom rate function that returns different rates for authenticated vs anonymous users.
    """
    if request.user.is_authenticated:
        return getattr(settings, 'RATE_LIMIT_AUTHENTICATED', '10/m')
    else:
        return getattr(settings, 'RATE_LIMIT_ANONYMOUS', '5/m')

@ratelimit(key=get_rate_limit_key, rate=get_rate_limit_rate, method='POST', block=True)
@csrf_protect
@require_http_methods(["GET", "POST"])
def login_view(request):
    """
    Login view with rate limiting.
    10 requests/minute for authenticated users, 5 requests/minute for anonymous users.
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if username and password:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                logger.info(f"Successful login for user: {username}")
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid username or password.')
                logger.warning(f"Failed login attempt for username: {username}")
        else:
            messages.error(request, 'Please provide both username and password.')
    
    return render(request, 'ip_tracking/login.html')

@ratelimit(key=get_rate_limit_key, rate=get_rate_limit_rate, method='POST', block=True)
@require_http_methods(["POST"])
def api_login(request):
    """
    API login endpoint with rate limiting.
    """
    try:
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if not username or not password:
            return JsonResponse({
                'error': 'Username and password are required'
            }, status=400)
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            logger.info(f"Successful API login for user: {username}")
            return JsonResponse({
                'success': True,
                'message': 'Login successful',
                'user_id': user.id,
                'username': user.username
            })
        else:
            logger.warning(f"Failed API login attempt for username: {username}")
            return JsonResponse({
                'error': 'Invalid credentials'
            }, status=401)
            
    except Exception as e:
        logger.error(f"Error in API login: {e}")
        return JsonResponse({
            'error': 'Internal server error'
        }, status=500)

@ratelimit(key=get_rate_limit_key, rate='20/m', method='GET', block=True)
def dashboard(request):
    """
    Dashboard view with rate limiting.
    """
    recent_logs = RequestLog.objects.all()[:10]
    blocked_ips_count = BlockedIP.objects.count()
    
    # Get some basic statistics
    total_requests = RequestLog.objects.count()
    unique_ips = RequestLog.objects.values('ip_address').distinct().count()
    
    context = {
        'recent_logs': recent_logs,
        'blocked_ips_count': blocked_ips_count,
        'total_requests': total_requests,
        'unique_ips': unique_ips,
    }
    
    return render(request, 'ip_tracking/dashboard.html', context)

@ratelimit(key=get_rate_limit_key, rate='30/m', method='GET', block=True)
def api_stats(request):
    """
    API endpoint for statistics with rate limiting.
    """
    try:
        # Get basic statistics
        total_requests = RequestLog.objects.count()
        unique_ips = RequestLog.objects.values('ip_address').distinct().count()
        blocked_ips_count = BlockedIP.objects.count()
        
        # Get country statistics
        country_stats = RequestLog.objects.values('country').annotate(
            count=models.Count('id')
        ).filter(
            country__isnull=False
        ).order_by('-count')[:10]
        
        return JsonResponse({
            'total_requests': total_requests,
            'unique_ips': unique_ips,
            'blocked_ips': blocked_ips_count,
            'top_countries': list(country_stats)
        })
        
    except Exception as e:
        logger.error(f"Error in API stats: {e}")
        return JsonResponse({
            'error': 'Internal server error'
        }, status=500)

@login_required
@ratelimit(key=get_rate_limit_key, rate='5/m', method='POST', block=True)
def block_ip_view(request):
    """
    View to block an IP address (admin only).
    """
    if not request.user.is_staff:
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        reason = request.POST.get('reason', '')
        
        if not ip_address:
            return JsonResponse({'error': 'IP address is required'}, status=400)
        
        # Validate IP address
        from django.core.validators import validate_ipv46_address
        from django.core.exceptions import ValidationError
        
        try:
            validate_ipv46_address(ip_address)
        except ValidationError:
            return JsonResponse({'error': 'Invalid IP address'}, status=400)
        
        # Create or update blocked IP
        blocked_ip, created = BlockedIP.objects.get_or_create(
            ip_address=ip_address,
            defaults={'reason': reason}
        )
        
        if not created:
            blocked_ip.reason = reason
            blocked_ip.save()
        
        # Clear cache for this IP
        from django.core.cache import cache
        cache.delete(f"blocked_ip_{ip_address}")
        
        logger.info(f"IP {ip_address} blocked by user {request.user.username}")
        
        return JsonResponse({
            'success': True,
            'message': f'IP {ip_address} has been blocked',
            'created': created
        })
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def ratelimit_handler(request, exception):
    """
    Custom handler for rate limit exceeded errors.
    """
    logger.warning(f"Rate limit exceeded for IP: {request.META.get('REMOTE_ADDR')}")
    
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Rate limit exceeded. Please try again later.',
            'retry_after': 60  # seconds
        }, status=429)
    else:
        return render(request, 'ip_tracking/rate_limit_exceeded.html', status=429)

# Test view for rate limiting
@ratelimit(key='ip', rate='3/m', method='GET', block=True)
def test_rate_limit(request):
    """
    Test view to verify rate limiting is working.
    """
    return JsonResponse({
        'message': 'Rate limit test successful',
        'ip': request.META.get('REMOTE_ADDR'),
        'user_authenticated': request.user.is_authenticated,
        'timestamp': timezone.now().isoformat()
    })