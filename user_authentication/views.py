from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from datetime import datetime
from django.conf import settings
from django.middleware import csrf
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer
from .utils import generate_otp, send_otp_email
from django.contrib.auth import get_user_model
from django_redis import get_redis_connection
import json
from datetime import timedelta
from django.utils.timezone import now
from rest_framework.permissions import AllowAny


User = get_user_model()


class LoginView(TokenObtainPairView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            tokens = response.data
            response = Response()

            # Set httpOnly cookies
            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                value=tokens['access'],
                expires=datetime.now() +
                settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
            )

            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                value=tokens['refresh'],
                expires=datetime.now() +
                settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
            )

            # Set CSRF token
            csrf.get_token(request)
            response.data = {"detail": "Login successful"}

            return response


class RefreshTokenView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get(
            settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])

        if refresh_token:
            request.data['refresh'] = refresh_token
            response = super().post(request, *args, **kwargs)

            if response.status_code == 200:
                response.set_cookie(
                    key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                    value=response.data['access'],
                    expires=datetime.now() +
                    settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                    secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                    httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                    samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                )

            return response

        return Response({"detail": "Refresh token not found"}, status=status.HTTP_401_UNAUTHORIZED)


class RegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)

        # Validate the user input
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data.get('email')
        user_data = serializer.validated_data.copy()  # Create a copy to modify

        try:
            # Handle profile picture separately
            profile_picture = user_data.pop('profile_picture', None)
            if profile_picture:
                # Store only the filename or relevant metadata
                user_data['profile_picture_name'] = profile_picture.name
                user_data['profile_picture_size'] = profile_picture.size
                user_data['profile_picture_content_type'] = profile_picture.content_type

            # Establish Redis connection
            redis_conn = get_redis_connection("default")

            # Store user data in Redis for 1 hour (3600 seconds)
            redis_conn.setex(
                email,
                3600,
                json.dumps(user_data).encode('utf-8')
            )

            # Generate OTP and store it in Redis for 1 minute (60 seconds)
            otp_code = generate_otp()
            print(otp_code)
            redis_conn.setex(f"otp_{email}", 60, str(otp_code))

            # Store OTP expiration time in Redis for 1 hour (3600 seconds)
            expiration_time = now() + timedelta(seconds=60)
            redis_conn.setex(
                f"expiration_{email}",
                3600,
                int(expiration_time.timestamp())
            )

            # If there's a profile picture, store it separately in Redis
            if profile_picture:
                redis_conn.setex(
                    f"profile_picture_{email}",
                    3600,
                    profile_picture.read()
                )

            # Send OTP to the user's email
            send_otp_email(email, otp_code)

            return Response(
                {
                    'message': 'Registration successful. Please verify your email with the OTP sent.',
                    'email': email
                },
                status=status.HTTP_201_CREATED
            )

        except ConnectionError:
            return Response(
                {'error': 'Failed to connect to Redis. Please try again later.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except (json.JSONDecodeError, TypeError) as e:
            return Response(
                {'error': 'Failed to process user data. Please contact support.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            # Log the actual error for debugging
            print(f"Unexpected error: {str(e)}")
            return Response(
                {'error': 'An unexpected error occurred. Please try again later.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class OTPVerificationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        """
        Handle POST request for OTP verification and user creation.
        """
        email = request.data.get('email')
        otp = request.data.get('otp')
        print(email, otp)

        if not email or not otp:
            return Response(
                {"message": "Email and OTP are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Establish Redis connection
            redis_conn = get_redis_connection("default")

            # Retrieve and verify OTP
            stored_otp = redis_conn.get(f"otp_{email}")
            print(stored_otp, otp)

            if not stored_otp or stored_otp.decode('utf-8') != otp:
                return Response(
                    {"message": "Invalid or expired OTP."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Check OTP expiration time
            expiration_time = redis_conn.get(f"expiration_{email}")
            if not expiration_time or float(expiration_time.decode('utf-8')) < now().timestamp():
                return Response(
                    {"message": "OTP has expired."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Retrieve user data from Redis
            user_data_json = redis_conn.get(email)
            if not user_data_json:
                return Response(
                    {"message": "User data not found in Redis."},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Deserialize user data
            try:
                user_data = json.loads(user_data_json.decode('utf-8'))
            except (json.JSONDecodeError, TypeError) as e:
                return Response(
                    {"message": "Failed to process user data. Please try again."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # Create user in database
            try:
                # Extract username from email if not provided
                if 'username' not in user_data:
                    user_data['username'] = email.split('@')[0]

                # Create user instance but don't save yet
                user = User(
                    email=email,
                    username=user_data['username'],
                )

                # Set password if provided
                if 'password' in user_data:
                    user.set_password(user_data['password'])

                # Save the user
                user.save()

                # Handle profile picture if it exists
                profile_picture_data = redis_conn.get(
                    f"profile_picture_{email}")
                if profile_picture_data:
                    from django.core.files.base import ContentFile
                    filename = user_data.get(
                        'profile_picture_name', 'profile.jpg')
                    user.profile_picture.save(
                        filename, ContentFile(profile_picture_data))

                # Clean up Redis data
                redis_conn.delete(email)
                redis_conn.delete(f"otp_{email}")
                redis_conn.delete(f"expiration_{email}")
                redis_conn.delete(f"profile_picture_{email}")

                # Generate tokens for automatic login
                from rest_framework_simplejwt.tokens import RefreshToken
                refresh = RefreshToken.for_user(user)

                response = Response({
                    "message": "User verified and created successfully.",
                    "email": user.email,
                    "username": user.username
                }, status=status.HTTP_201_CREATED)

                # Set JWT cookies
                response.set_cookie(
                    key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                    value=str(refresh.access_token),
                    expires=datetime.now() +
                    settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                    secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                    httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                    samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                )

                response.set_cookie(
                    key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                    value=str(refresh),
                    expires=datetime.now() +
                    settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                    secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                    httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                    samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                )

                return response

            except Exception as e:
                print(f"Error creating user: {str(e)}")
                return Response(
                    {"message": "Failed to create user account."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except ConnectionError:
            return Response(
                {"message": "Failed to connect to Redis. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            print(f"Unexpected error during OTP verification: {e}")
            return Response(
                {"message": "An unexpected error occurred. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ResendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        """
        Handle POST request for resending OTP.

        Args:
            request (Request): The HTTP request containing data for resending OTP.

        Returns:
            Response: Contains the status of OTP resend operation.
        """
        email = request.data.get('email')

        if not email:
            return Response(
                {"message": "Email is required to resend OTP."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Establish Redis connection
            redis_conn = get_redis_connection("default")

            # Check if user data exists in Redis
            user_data_json = redis_conn.get(email)
            if not user_data_json:
                return Response(
                    {"message": "User data not found. Please register again."},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Generate a new OTP
            otp_code = generate_otp()
            print(otp_code)
            otp_key = f"otp_{email}"
            redis_conn.setex(otp_key, 60, str(otp_code))

            # Set expiration time for OTP verification
            expiration_time = now() + timedelta(seconds=60)
            expiration_seconds = int(expiration_time.timestamp())
            expiration_key = f"expiration_{email}"
            redis_conn.setex(expiration_key, 60, expiration_seconds)

            # Send OTP via email
            try:
                send_otp_email(email, otp_code)
            except Exception as e:
                print(f"Failed to send email: {e}")
                return Response(
                    {"message": "Failed to send OTP email. Please try again later."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response(
                {
                    "message": "OTP resent successfully.",
                    "timer": expiration_time.isoformat(),
                },
                status=status.HTTP_200_OK
            )

        except ConnectionError:
            return Response(
                {"message": "Failed to connect to Redis. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            print(f"Unexpected error during OTP resend: {e}")
            return Response(
                {"message": "An unexpected error occurred. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        response = Response({"detail": "Successfully logged out"})
        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        return response
