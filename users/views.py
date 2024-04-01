from rest_framework.views import APIView
from rest_framework import status, serializers
from rest_framework.response import Response
from .serializers import UserSerializer
from .models import User
from .token_utils import generate_access_token, generate_refresh_token, validate_refresh_token ,validate_access_token

class RegisterView(APIView):
    """
    API endpoint for user registration.

    POST request:
    - Registers a new user with provided data.
    - Returns the serialized user data with status 201 (Created).
    """
    def post(self, request):
        email = request.data.get('email')

        # Check if the email domain is allowed
        if not email.endswith('thedevopsteam.com'):
            error_message = 'Invalid credentials! Email domain is not allowed.'
            return Response({'error': error_message}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
        except serializers.ValidationError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    """
    API endpoint for user login.

    POST request:
    - Authenticates user with provided email and password.
    - Generates JWT token for authenticated user.
    - Sets JWT token in HTTP-only cookie.
    """
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if email.endswith('thedevopsteam.com'):

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                error_message = 'Invalid credentials! Email does not exist.'
                return Response({'error': error_message}, status=status.HTTP_400_BAD_REQUEST)

            if not user.check_password(password):
                error_message = 'Invalid credentials! Incorrect password.'
                return Response({'error': error_message}, status=status.HTTP_400_BAD_REQUEST)
            
            # Generate access token
            access_token = generate_access_token(user)

            # Generate refresh token
            refresh_token = generate_refresh_token(user)

            # Set refresh token in cookie
            response = Response({'access_token': access_token})
            response.set_cookie(key='refresh_token', value=refresh_token, httponly=True)
            
            return response

        else:
            error_message = 'Invalid credentials! Email domain is not allowed.'
            return Response({'error': error_message}, status=status.HTTP_400_BAD_REQUEST)


class UserInfoView(APIView):
    """
    API endpoint to fetch user information.

    GET request:
    - Returns the user ID and first name.
    """
    def get(self, request):
        # Validate the access token and retrieve the user ID
        payload, error_response = validate_access_token(request)
        if error_response:
            return error_response

        user_id = payload.get('id')

        try:
            # Fetch the user from the database
            user = User.objects.get(id=user_id)
            user_info = {
                'user_id': user.id,
                'first_name': user.name
            }
            return Response(user_info, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)


class RefreshTokenView(APIView):
    def post(self, request):
        # Check if the refresh token is provided in the request
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return Response({'error': 'Refresh token not provided.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Validate the refresh token
        payload = validate_refresh_token(refresh_token)
        if payload:
            user_id = payload['id']
            user = User.objects.get(id=user_id)
            new_access_token = generate_access_token(user)
            return Response({'access_token': new_access_token}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Failed to refresh access token.'}, status=status.HTTP_401_UNAUTHORIZED)
