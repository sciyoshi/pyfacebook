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
    def get_app_url(self):
        """Get the URL for this app's canvas page, according to app_name."""
        return 'http://apps.facebook.com/%s/' % self.app_name

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
    try:
        return _thread_locals.facebook
    except AttributeError:
        raise ImproperlyConfigured('Make sure you have the Facebook middleware installed.')


def require_login(next=None, internal=True):
    """
    Decorator for Django views that requires the user to be logged in.
    The FacebookMiddleware must be installed.

    @require_login()
    def some_view(request):
        ...

    """
    def decorator(view):
        def newview(request, *args, **kwargs):
            next = newview.next
            internal = newview.internal

            try:
                fb = request.facebook
            except:
                raise ImproperlyConfigured('Make sure you have the Facebook middleware installed.')

            if callable(next):
                next = next(request.path)
            elif isinstance(next, int):
                next = '/'.join(request.path.split('/')[next + 1:])
            elif next is None and fb.callback_path and request.path.startswith(fb.callback_path):
                next = request.path[len(fb.callback_path):]
            else:
                next = ''

            result = fb.check_session(request, next)

            if result:
                return result

            if internal and request.method == 'GET' and fb.app_name:
                return request.facebook.redirect('%s%s' % (fb.get_app_url(), next))

            return view(request, *args, **kwargs)
        newview.next = next
        newview.internal = internal
        return newview
    return decorator


def require_add(next=''):
    def decorator(view):
        return require_login(next)(view)
    return decorator


class FacebookMiddleware(object):
    """
    Middleware that attaches a Facebook object to every incoming request.
    The Facebook object created can also be accessed from models for the
    current thread by using get_facebook_client().

    """

    def __init__(self, api_key=None, secret_key=None, app_name=None, callback_path=None):
        self.api_key = api_key or settings.FACEBOOK_API_KEY
        self.secret_key = secret_key or settings.FACEBOOK_SECRET_KEY
        self.app_name = app_name or getattr(settings, 'FACEBOOK_APP_NAME', None)
        self.callback_path = callback_path or getattr(settings, 'FACEBOOK_CALLBACK_PATH', None)

    def process_request(self, request):
        _thread_locals.facebook = request.facebook = Facebook(self.api_key, self.secret_key, app_name=self.app_name, callback_path=self.callback_path)
