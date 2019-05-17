1. add 'cbauth', rest_framework and allauth in INSTALLED_APPS:

```
INSTALLED_APPS = [
    ...
    'rest_framework',
    'rest_framework_simplejwt.token_blacklist',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.facebook',
    'allauth.socialaccount.providers.google',
    'cbauth',
]
```

2. Setup rest framework:

```
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
        'rest_framework.permissions.AllowAny',
    ),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}
```

3. Time expiration token:

```
from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),
}
```

4. Include urls:

```
from django.urls import path, include

urlpatterns = [
    ...
    path('api/auth/', include('cbauth.urls.api'), name="cbauth_api"),
]
```


Publish
=================================

```
python setup.py sdist
pip install twine
twine upload dist/*
```
