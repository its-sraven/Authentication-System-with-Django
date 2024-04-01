import jwt
import datetime
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response

JWT_SECRET = 'f0nd0j2i34#u12h#ej3d45f#3h!k2i12n0*89g'

def generate_access_token(user):
    """
    Generate access token for the given user.
    """
    payload = {
        'id': user.id,
        'exp': timezone.now() + datetime.timedelta(minutes=15),
        'iat': timezone.now()
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token

def generate_refresh_token(user):
    """
    Generate refresh token for the given user.
    """
    payload = {
        'id': user.id,
        'exp': timezone.now() + datetime.timedelta(minutes=30),
        'iat': timezone.now()
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token


def validate_refresh_token(refresh_token):
    try:
        # Validate the refresh token
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=['HS256'])
        return payload  # Return the payload if the token is valid
    except jwt.ExpiredSignatureError:
        return None, Response({'error': 'Refresh token expired'}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError:
        return None  ,Response({'error': 'Invalid Refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

def validate_access_token(request):
    try:
        # Extract the access token from the Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or 'Bearer ' not in auth_header:
            return None, 'Access token not provided or invalid'

        access_token = auth_header.split('Bearer ')[1]

        # Validate the access token
        payload = jwt.decode(access_token, JWT_SECRET, algorithms=['HS256'])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, Response({'error': 'Access token expired'}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError:
        return None, Response({'error': 'Invalid access token'}, status=status.HTTP_401_UNAUTHORIZED)
