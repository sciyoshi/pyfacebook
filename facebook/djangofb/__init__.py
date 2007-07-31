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


def require_login(next='', internal=True):
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


if __name__ == '__main__':
    import sys, os

    def usage():
        sys.stderr.write('Usage: djangofb.py startapp <appname>')
        sys.exit(1)

    if len(sys.argv) not in (2, 3):
        usage()

    if sys.argv[1] != 'startapp':
        usage()

    app_name = len(sys.argv) == 3 and sys.argv[2] or 'fbapp'

    try:
        sys.path.insert(0, os.getcwd())
        import settings # Assumed to be in the same directory or current directory.
    except ImportError:
        sys.stderr.write("Error: Can't find the file 'settings.py' in the directory containing %r or in the current directory. It appears you've customized things.\nYou'll have to run django-admin.py, passing it your settings module.\n(If the file settings.py does indeed exist, it's causing an ImportError somehow.)\n" % __file__)
        sys.exit(1)

    from django.core import management
    
    directory = management.setup_environ(settings)

    project_dir = os.path.normpath(os.path.join(directory, '..'))
    parent_dir = os.path.basename(project_dir)
    project_name = os.path.basename(directory)
    if app_name == project_name:
        sys.stderr.write(management.style.ERROR('Error: You cannot create an app with the same name (%r) as your project.\n' % app_name))
        sys.exit(1)
    if app_name == 'facebook':
        sys.stderr.write(management.style.ERROR('Error: You cannot name your app "facebook", since this can cause conflicts with imports in Python < 2.5.\n'))
        sys.exit(1)
    if not management._is_valid_dir_name(app_name):
        sys.stderr.write(management.style.ERROR('Error: %r is not a valid app name. Please use only numbers, letters and underscores.\n' % (app_name)))
        sys.exit(1)

    top_dir = os.path.join(directory, app_name)
    try:
        os.mkdir(top_dir)
    except OSError, e:
        sys.stderr.write(management.style.ERROR("Error: %s\n" % e))
        sys.exit(1)

    import facebook

    template_dir = os.path.join(facebook.__path__[0], 'djangofb', 'default_app')

    sys.stderr.write('Creating Facebook application %r...\n' % app_name)
    
    for d, subdirs, files in os.walk(template_dir):
        relative_dir = d[len(template_dir) + 1:]
        if relative_dir:
            os.mkdir(os.path.join(top_dir, relative_dir))
        subdirs[:] = [s for s in subdirs if s.startswith('.')]
        for f in files:
            if f.endswith('.pyc'):
                continue
            path_old = os.path.join(d, f)
            path_new = os.path.join(top_dir, relative_dir, f)
            f_old = open(path_old, 'r')
            f_new = open(path_new, 'w')
            sys.stderr.write('Writing %s...\n' % path_new)
            f_new.write(f_old.read().replace('{{ project }}', project_name).replace('{{ app }}', app_name))
            f_new.close()
            f_old.close()

    sys.stderr.write('Done!\n\n')
    
    from django.conf import settings
    
    need_api_key = not hasattr(settings, 'FACEBOOK_API_KEY')
    need_middleware = not 'facebook.djangofb.FacebookMiddleware' in settings.MIDDLEWARE_CLASSES
    need_loader = not 'django.template.loaders.app_directories.load_template_source' in settings.TEMPLATE_LOADERS
    need_install_app = not '%s.%s' % (project_name, app_name) in settings.INSTALLED_APPS

    if need_api_key or need_middleware or need_loader or need_install_app:
        sys.stderr.write("""There are a couple of things you NEED to do before you can use this app:\n\n""")
        if need_api_key:
            sys.stderr.write(""" * Set FACEBOOK_API_KEY and FACEBOOK_SECRET_KEY to the appropriate values in settings.py\n\n""")
        if need_middleware:
            sys.stderr.write(""" * Add 'facebook.djangofb.FacebookMiddleware' to your MIDDLEWARE_CLASSES in settings.py\n\n""")
        if need_loader:
            sys.stderr.write(""" * Add 'django.template.loaders.app_directories.load_template_source' to your TEMPLATE_LOADERS in settings.py\n\n""")
        if need_install_app:
            sys.stderr.write(""" * Add '%s.%s' to your INSTALLED_APPS in settings.py\n\n""" % (project_name, app_name))

    sys.stderr.write("""The final step is to add (r'^%s/', include('%s.%s.urls')) to your urls.py, and then set your callback page in the application settings on Facebook to 'http://your.domain.com/%s/'.

Good luck!""" % (project_name, project_name, app_name, project_name))
