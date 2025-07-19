from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('ip-tracking/', include('ip_tracking.urls')),
    path('', RedirectView.as_view(url='/ip-tracking/dashboard/')),
]

# Custom handler for rate limit exceptions
handler429 = 'ip_tracking.views.ratelimit_handler'