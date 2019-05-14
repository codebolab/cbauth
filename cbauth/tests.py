# -*- coding: utf-8 -*-
import logging

from django.urls import reverse
from django.test import TestCase
from django.test.client import Client


class TestBase(TestCase):
    def setUp(self):
        self.log = logging.getLogger('simple')
        self.client = Client()

    def request(self, method, path, data=None, **kwargs):
        if self.secure:
            kwargs['wsgi.url_scheme'] = 'https'

        CALLS = {
            'get': self.client.get,
            'post': self.client.post,
            'put': self.client.put,
            'delete': self.client.delete,
        }

        method = method.lower()
        if method not in CALLS:
            raise ValueError()

        call = CALLS.get(method)
        return call(path, data=data, **kwargs)


class TestLogin(TestBase):
    login_data = {
        'username': 'fakeuser',
        'password': 'fakepass'
    }
    secure = False
    fixtures = ['auth.json']

    def setUp(self):
        TestBase.setUp(self)

        self.login_url = reverse('admin:index')
        self.logout_url = reverse('admin:logout')

    def test_get_token(self):
        response = self.request('post', reverse('token_obtain_pair'),
                                data=self.login_data)
        self.log.info('response: %s ' % response)

    def test_login(self):
        response = self.request('post', reverse('auth_login'),
                                data=self.login_data)
        assert response.status_code == 302

    def test_get_login(self):
        response = self.request('get', reverse('auth_login'))
        self.log.info("login status code: %s" % response.content)
        self.log.info("response: %s " % response)
        self.log.info("login status code: %s" % response.status_code)
        assert response.status_code == 200

    def test_on_invalid_data(self):
        data = {
            'username': 'fakeuser',
            'password': 'invalidpass'
        }
        response = self.request('post', reverse('auth_login'),
                                data=data)
        self.assertEquals(response.status_code, 200)

    def test_login_fail_when_empty(self):
        data = {
            'username': 'fakeuser',
            'password': ''
        }
        response = self.request('post', reverse('auth_login'),
                                data=data)
        self.log.info('response: %s ' % response)
        self.assertEquals(response.status_code, 200)


class TestAPI(TestBase):
    login_data = {
        'username': 'fakeuser',
        'password': 'fakepass'
    }
    secure = False
    fixtures = ['auth.json']

    def test_login(self):
        response = self.request('post', reverse('api_login'),
                                data=self.login_data)
        self.log.info('response.class: %s ' % response.__class__)
        self.log.info('response.data: %s ' % response.data)
        self.log.info('response.status_code: %s ' % response.status_code)
        self.assertEquals(response.status_code, 200)
        self.assertIn('username', response.data)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_login_invalid(self):
        data = {
            'username': 'fakeuser',
            'password': 'invalidpass'
        }
        response = self.request('post', reverse('api_login'), data=data)
        self.log.info('response.class: %s ' % response.__class__)
        self.log.info('response.data: %s ' % response.data)
        self.log.info('response.status_code: %s ' % response.status_code)
        self.assertEquals(response.status_code, 400)

    def test_me(self):
        # Calls fail
        response = self.request('get', reverse('api_me'))
        self.assertEquals(response.status_code, 403)

        # Calls login
        response = self.request('post', reverse('api_login'),
                                data=self.login_data)

        access_token = response.data.get('access')
        refresh_token = response.data.get('refresh')

        self.log.info("access_token: %s " % access_token)
        self.log.info("refresh_token: %s " % refresh_token)

        # Access fail without token after calling login
        response = self.request('get', reverse('api_me'))
        self.assertEquals(response.status_code, 403)

        # Access with token
        headers = {'HTTP_AUTHORIZATION': 'Bearer %s' % access_token}
        response = self.request('get', reverse('api_me'), **headers)
        self.log.info("response: %s " % response)
        self.log.info("response.data: %s " % response.data)
        self.assertEquals(response.status_code, 200)

    def test_logout(self):
        # Calls login
        response = self.request('post', reverse('api_login'),
                                data=self.login_data)

        access_token = response.data.get('access')
        # refresh_token = response.data.get('refresh')

        headers = {'HTTP_AUTHORIZATION': 'Bearer %s' % access_token}

        response = self.request('get', reverse('api_me'), **headers)
        self.log.info("response: %s " % response)
        self.log.info("response.data: %s " % response.data)
        self.assertEquals(response.status_code, 200)

        response = self.request('post', reverse('api_logout'), **headers)
        self.log.info("response: %s " % response)
        self.log.info("response.data: %s " % response.data)
        self.assertEquals(response.status_code, 200)

        response = self.request('get', reverse('api_me'), **headers)
        self.log.info("response: %s " % response)
        self.log.info("response.data: %s " % response.data)
        self.assertNotEquals(response.status_code, 200)
