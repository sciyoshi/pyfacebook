#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='pyfacebook',
      version='1.0a2',
      description='Python Client Library for the Facebook API',
      author='Samuel Cormier-Iijima',
      author_email='sciyoshi@gmail.com',
      url='http://code.google.com/p/pyfacebook',
      packages=['facebook',
                'facebook.djangofb',
                'facebook.djangofb.default_app'],
      test_suite='tests',
      tests_require=['MiniMock'])
