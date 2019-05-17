import logging

from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth.forms import AuthenticationForm

from django.utils.translation import ugettext_lazy as _

from rest_framework import generics
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework import permissions, status
from rest_framework_simplejwt.tokens import RefreshToken


logger = logging.getLogger('simple')


# RESTfull API Views
# ---------------------------------------------------------
class AuthMixin(object):
    def get(self, request, *args, **kwargs):
        response = {
            'message': _(u'Only POST method is allowed')
        }
        return Response(response, status=405)


class APIMeView(generics.GenericAPIView):
    permission_classes = (IsAuthenticatedOrReadOnly,)

    def get(self, request):
        """
        Returns user information
        """

        user = request.user
        if not user.is_anonymous:
            data = {
                'username': user.username,
                'email': user.email,
            }
            return Response(data, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'no user'}, status=403)


class APILoginView(AuthMixin, generics.GenericAPIView):
    """
    Async Login API endpoint
    """

    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        form = AuthenticationForm(request, data=request.data)
        if form.is_valid():

            user = form.get_user()

            if getattr(settings, 'CB_GENERATE_COOKIE', False):
                login(request, user)

            refresh = RefreshToken.for_user(user)

            response = {
                'username': user.username,
                'refresh': str(refresh),
                'access': str(refresh.access_token)
            }

            return Response(response)
        else:
            response = {
                'errors': form.errors
            }
            return Response(response, status=400)


class APILogoutView(AuthMixin, generics.GenericAPIView):
    """
    Async Logout API endpoint
    """

    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        header = request.META.get('HTTP_AUTHORIZATION')

        if header is not None:
            parts = header.split()
            logger.info("parts: %s " % parts)
            token = RefreshToken(token=parts[1])
            token.blacklist()

        if getattr(settings, 'CB_GENERATE_COOKIE', False):
            logout(request)

        return Response({"detail": _("Successfully logged out.")},
                        status=status.HTTP_200_OK)
