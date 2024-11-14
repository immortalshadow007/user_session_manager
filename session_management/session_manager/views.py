import jwt
import os
import logging
from django.shortcuts import render
from django.middleware.csrf import get_token
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from django.http import JsonResponse
from rest_framework import status
from datetime import datetime, timezone
from .models import UserProfile, Session, UserAction
from .serializers import SessionSerializer, UserActionSerializer

logger = logging.getLogger(__name__)

class CreateSessionView(APIView):
    def post(self, request):
        mobile_number_hash = request.data.get('mobile_number_hash')
        mobile_number = request.data.get('mobile_number')

        if not mobile_number_hash or not mobile_number:
            logger.error("Missing mobile_number_hash or mobile_number in the request.")
            return Response({'error': 'Missing mobile_number_hash or mobile_number.'}, status=status.HTTP_400_BAD_REQUEST)
        
        calculated_hash = UserProfile.hash_mobile_number(mobile_number)
        if calculated_hash != mobile_number_hash:
            logger.error("mobile_number_hash does not match the hash of mobile_number.")
            return Response({'error': 'Invalid mobile number or hash.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Check if user profile already exists
            existing_user = UserProfile.objects(mobile_number_hash=mobile_number_hash).first()
            if existing_user:
                uid = existing_user.UID
                # Update last_login field
                existing_user.last_login = datetime.now(timezone.utc)
                existing_user.save()
            else:
                # Create user profile
                user_profile = UserProfile.create_user_profile(mobile_number)
                uid = user_profile.UID

            # Create session
            mongo_session = Session.create_session(uid)

            # Serialize session data
            response_data = {
                'session_token': mongo_session.session_token,
                'expires_at': mongo_session.expires_at.isoformat(),
                'is_active': mongo_session.is_active
            }

            # Prepare the response
            response = Response(response_data, status=status.HTTP_200_OK)

            # Set HttpOnly cookie for session_token
            response.set_cookie(
                key='session_token',
                value=mongo_session.session_token,
                httponly=True,
                secure=True if os.getenv('NODE_ENV') == 'production' else False,
                max_age=60 * 60 * 24 * 1,  # 1 day
                samesite='Lax',
                path='/',
            )

            # Set a cookie for uid
            response.set_cookie(
                key='uid',
                value=uid,
                httponly=False,
                secure=True if os.getenv('NODE_ENV') == 'production' else False,
                max_age=60 * 60 * 24 * 1,  # 1 day
                samesite='Lax',
                path='/',
            )

            return response

        except Exception as e:
            logger.error(f"Error during account and session creation: {str(e)}")
            return Response({'error': 'An error occurred during account and session creation.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetCSRFTokenView(APIView):
    def get(self, request):
        csrf_token = get_token(request)
        return Response({'csrfToken': csrf_token}, status=status.HTTP_200_OK)

class ValidateSessionView(APIView):
    """
    API View to validate a user's session token and apply sliding session expiration
    """
    def get(self, request):
        # Get the session token from the request cookies
        session_token = request.COOKIES.get('session_token')

        # Validate the session using the updated sliding session logic
        session = Session.validate_session(session_token)
        
        if session:
            # If session is valid, check if the token has been refreshed
            response_data = {
                'status': 'success',
                'message': 'Session is valid',
            }
            
            # No token refresh was needed, so just return the valid session info
            return Response(response_data, status=status.HTTP_200_OK)
        
        # If the session is invalid or expired, return an error
        return Response({
            'status': 'failed',
            'message': 'Session is invalid or has expired',
        }, status=status.HTTP_401_UNAUTHORIZED)

class TerminateSessionView(APIView):
    def get(self, request):
        try:
            # Retrieve session token from cookies
            token = request.COOKIES.get('session_token', '')
            if token:
                # Decode the JWT token
                payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
                uid = payload['uid']
                # Retrieve and invalidate the session
                mongo_session = Session.objects(session_token=token, uid=uid, is_active=True).first()
                if mongo_session:
                    # Set is_active to False and delete the session document
                    mongo_session.terminate()
                    
                    # Prepare response
                    response = Response({'success': True}, status=status.HTTP_200_OK)
                    # Delete 'session_token' and 'uid' cookies
                    response.delete_cookie('session_token', path='/')
                    response.delete_cookie('uid', path='/')
                    return response
                else:
                    return Response({'error': 'Session not found or already terminated'}, status=status.HTTP_404_NOT_FOUND)
            else:
                return Response({'error': 'No session token provided'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error during session termination: {str(e)}")
            return Response({'error': 'An error occurred during session termination.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LogUserActionView(APIView):
    def post(self, request):
        if hasattr(request, 'uid'):
            data = request.data.copy()
            data['uid'] = request.uid

            serializer = UserActionSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({'status': 'Action logged'}, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Invalid session'}, status=status.HTTP_401_UNAUTHORIZED)

