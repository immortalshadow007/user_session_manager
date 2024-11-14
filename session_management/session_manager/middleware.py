from django.utils import timezone
from django.conf import settings
from django.http import JsonResponse
from .models import Session
import jwt

class SessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.exempt_urls = [
            '/api/session_manager/create-session/',
            '/api/session_manager/get-csrf-token/',
            '/api/session_manager/terminate-session/',
        ]

    def __call__(self, request):
        # Process the request
        request = self.process_request(request)

        # Get the response from the next middleware or view
        response = self.get_response(request)

        # Process the response
        response = self.process_response(request, response)

        return response

    def process_request(self, request):
        if request.path in self.exempt_urls:
            return request
        # Extract the session token from the request headers
        token = request.COOKIES.get('session_token', '')
        if token:
            try:
                # Decode the JWT token
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
                uid = payload['uid']
                # Retrieve the session
                session = Session.objects.get(session_token=token, uid=uid, is_active=True)
                # Check if session is expired
                if session.is_active:
                    session.expires_at=timezone.now() + timezone.timedelta(minutes=15)
                    session.save()
                    request.session = session
                    request.uid = uid
                else:
                    request.session_expired = True
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, Session.DoesNotExist):
                request.invalid_session = True
        else:
            request.no_session = True
        return request

    def process_response(self, request, response):
        if request.path in self.exempt_urls:
            return response
        # Handle user session errors
        if hasattr(request, 'session_expired') and request.session_expired:
            return JsonResponse({'error': 'Session expired'}, status=401)
        elif hasattr(request, 'invalid_session') and request.invalid_session:
            return JsonResponse({'error': 'Invalid session'}, status=401)
        elif hasattr(request, 'no_session') and request.no_session:
            return JsonResponse({'error': 'No session found'}, status=401)
        return response
