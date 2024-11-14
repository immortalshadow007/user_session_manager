from django.urls import path
from .views import (
    CreateSessionView,
    GetCSRFTokenView,
    ValidateSessionView,
    TerminateSessionView,
    LogUserActionView,
)

urlpatterns = [
    path('create-session/', CreateSessionView.as_view(), name='create_session'),
    path('get-csrf-token/', GetCSRFTokenView.as_view(), name='get-csrf-token'),
    path('validate-session/', ValidateSessionView.as_view(), name='validate_session'),
    path('terminate-session/', TerminateSessionView.as_view(), name='terminate_session'),
    path('log-user-action/', LogUserActionView.as_view(), name='log_user_action'),
]
