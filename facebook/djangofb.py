__all__ = ['Facebook', 'FacebookMiddleware', 'get_facebook_client', 'require_login']

import facebook

from django.http import HttpResponse, HttpResponseRedirect
from django.core.exceptions import ImproperlyConfigured
from django.conf import settings

try:
    from threading import local
except ImportError:
    from django.utils._threading_local import local

_thread_locals = local()

class Facebook(facebook.Facebook):
    def redirect(self, url):
        """
        Helper for Django which redirects to another page. If inside a
        canvas page, writes a <fb:redirect> instead to achieve the same effect.

        """
        if self.in_canvas:
            return HttpResponse('<fb:redirect url="%s" />' % (url, ))
        else:
            return HttpResponseRedirect(url)


def get_facebook_client():
    """
    Get the current Facebook object for the calling thread.

    """
    return getattr(_thread_locals, 'facebook', None)


def require_login(next=''):
    """
    Decorator for Django views that requires the user to be logged in.
    The FacebookMiddleware must be installed.

    @require_login_next()
    def some_view(request):
        ...

    """
    def decorator(view):
        def newview(request, *args, **kwargs):
            try:
                fb = request.facebook
            except:
                raise ImproperlyConfigured('Make sure you have the Facebook middleware installed.')

            result = fb.check_session(request, next)

            if result:
                return result

            return view(request, *args, **kwargs)
        return newview
    return decorator


def require_add(next=''):
    pass


class FacebookMiddleware(object):
    """
    Middleware that attaches a Facebook object to every incoming request.
    The Facebook object created can also be accessed from models for the
    current thread by using get_facebook_client().

    """

    def __init__(self, api_key=None, secret_key=None):
        self.api_key = api_key or settings.FACEBOOK_API_KEY
        self.secret_key = secret_key or settings.FACEBOOK_SECRET_KEY

    def process_request(self, request):
        _thread_locals.facebook = request.facebook = Facebook(self.api_key, self.secret_key)
