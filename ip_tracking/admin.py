from django.contrib import admin
from .models import RequestLog, BlockedIP

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'path', 'country', 'city', 'timestamp']
    list_filter = ['country', 'city', 'timestamp']
    search_fields = ['ip_address', 'path', 'country', 'city']
    readonly_fields = ['ip_address', 'timestamp', 'path', 'country', 'city']
    
    def has_add_permission(self, request):
        return False

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'reason', 'created_at']
    list_filter = ['created_at']
    search_fields = ['ip_address', 'reason']