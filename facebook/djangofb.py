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

            if internal and request.method == 'GET' and self.app_name:
                return request.facebook.redirect('%s%s' % (self.get_app_url(), next))

            return view(request, *args, **kwargs)
        newview.next = next
        newview.internal = internal
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

    def __init__(self, api_key=None, secret_key=None, app_name=None):
        self.api_key = api_key or settings.FACEBOOK_API_KEY
        self.secret_key = secret_key or settings.FACEBOOK_SECRET_KEY
        self.app_name = app_name or getattr(settings, 'FACEBOOK_APP_NAME', None)

    def process_request(self, request):
        _thread_locals.facebook = request.facebook = Facebook(self.api_key, self.secret_key, app_name=self.app_name)


if __name__ == '__main__':
    import sys, os

    DEFAULT_MODELS_PY = '''\
from django.db import models

# get_facebook_client lets us get the current Facebook object
# from outside of a view, which lets us have cleaner code
from facebook.djangofb import get_facebook_client

class UserManager(models.Manager):
    """Custom manager for a Facebook User."""
    
    def get_current(self):
        """Gets a User object for the logged-in Facebook user."""
        facebook = get_facebook_client()
        user, created = self.get_or_create(id=int(facebook.uid))
        if created:
            # we could do some custom actions for new users here...
            pass
        return user

class User(models.Model):
    """A simple User model for Facebook users."""

    # We use the user's UID as the primary key in our database.
    id = models.IntegerField(primary_key=True)

    # TODO: The data that you want to store for each user would go here.
    # For this sample, we let users let people know their favorite progamming
    # language, in the spirit of Extended Info.
    language = models.CharField(maxlength=64, default='Python')

    # Add the custom manager
    objects = UserManager()
'''

    DEFAULT_VIEWS_PY = '''\
from django.http import HttpResponse
from django.views.generic.simple import direct_to_template

# Import the Django helpers
import facebook.djangofb as facebook

# The User model defined in models.py
from models import User

# We store our apps' canvas page URL here, so that
# we can redirect to it if somebody tries to access
# our pages directly. If you are writing an external
# Facebook app, you wouldn't need this.
app_url = 'http://apps.facebook.com/canvaspage/'

# We'll require login for our canvas page. This
# isn't necessarily a good idea, as we might want
# to let users see the page without granting our app
# access to their info. See the wiki for details on how
# to do this.
@facebook.require_login()
def canvas(request):
    # For internal apps, we'd rather not have users see our
    # pages from outside Facebook. We check if the request
    # is a GET, and if it is, redirect to the appropriate page.
    # (This is pretty ugly to have to do in every view, and
    # may be pulled into a helper function.)
    if request.method == 'GET':
        return request.facebook.redirect(app_url)

    # Get the User object for the currently logged in user
    user = User.objects.get_current()

    # Check if we were POSTed the user's new language of choice
    if 'language' in request.POST:
        user.language = request.POST['language'][:64]
        user.save()

    # User is guaranteed to be logged in, so pass canvas.fbml
    # an extra 'fbuser' parameter that is the User object for
    # the currently logged in user.
    return direct_to_template(request, 'canvas.fbml', extra_context={'fbuser': user})
'''

    DEFAULT_URLS_PY = '''\
from django.conf.urls.defaults import *

urlpatterns = patterns('%s.%s.views',
    (r'^$', 'canvas'),
    # Define other pages you want to create here
)
'''

    DEFAULT_CANVAS_FBML = '''\
<div style="padding: 20px;">
  {% comment %}
    We can use {{ fbuser }} to get at the current user.
    {{ fbuser.id }} will be the user's UID, and {{ fbuser.language }}
    is his/her favorite language (Python :-).
  {% endcomment %}
  <h3>Hello, <fb:name uid="{{ fbuser.id }}" firstnameonly="true" useyou="false" />!</h3>

  Your favorite language is {{ fbuser.language|escape }}.

  <form action="." method="POST">
    <input type="text" name="language" value="{{ fbuser.language|escape }}" />
    <input type="submit" value="Change" />
  </form>
</div>
'''

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
    
    sys.stderr.write('Creating Facebook application %r...\n' % app_name)
    p = os.path.join(top_dir, '__init__.py')
    sys.stderr.write('Writing %s...\n' % p)
    f = open(p, 'w')
    f.close()
    p = os.path.join(top_dir, 'views.py')
    sys.stderr.write('Writing %s...\n' % p)
    f = open(p, 'w')
    f.write(DEFAULT_VIEWS_PY)
    f.close()
    p = os.path.join(top_dir, 'models.py')
    sys.stderr.write('Writing %s...\n' % p)
    f = open(p, 'w')
    f.write(DEFAULT_MODELS_PY)
    f.close()
    p = os.path.join(top_dir, 'urls.py')
    sys.stderr.write('Writing %s...\n' % p)
    f = open(p, 'w')
    f.write(DEFAULT_URLS_PY % (project_name, app_name))
    f.close()
    os.mkdir(os.path.join(top_dir, 'templates'))
    p = os.path.join(top_dir, 'templates', 'canvas.fbml')
    sys.stderr.write('Writing %s...\n' % p)
    f = open(p, 'w')
    f.write(DEFAULT_CANVAS_FBML)
    f.close()
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
