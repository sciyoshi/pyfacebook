from facebook import Facebook

__docformat__ = "restructuredtext"

# Setup Paste, if available.  This needs to stay in the same module as
# FacebookWSGIMiddleware below.
try:
    from paste.registry import StackedObjectProxy
except ImportError:
    pass
else:
    facebook = StackedObjectProxy(name="PyFacebook Facebook Connection")


class FacebookWSGIMiddleware(object):
    """This is WSGI middleware for Facebook."""

    def __init__(self, app, config, facebook_class=Facebook):
        """Initialize the Facebook middleware.

        ``app``
        This is the WSGI application being wrapped.

        ``config``
        This is a dict containing the keys "pyfacebook.apikey" and
        "pyfacebook.secret".

        ``facebook_class``
        If you want to subclass the Facebook class, you can pass in
        your replacement here.  Pylons users will want to use
        PylonsFacebook.

        """
        self.app = app
        self.config = config
        self.facebook_class = facebook_class

    def __call__(self, environ, start_response):
        config = self.config
        real_facebook = self.facebook_class(config["pyfacebook.apikey"], config["pyfacebook.secret"])
        registry = environ.get('paste.registry')
        if registry:
            registry.register(facebook, real_facebook)
        environ['pyfacebook.facebook'] = real_facebook
        return self.app(environ, start_response)


try:
    from decorator import decorator
    from paste.httpexceptions import HTTPFound
    import pylons
    from webhelpers import url_for
except ImportError:
    pass
else:
    class PylonsFacebook(AbstractFacebook):
        """This is a Pylons implementation of Facebook."""

        def redirect(self, text):
            if self.in_canvas:
                return pylons.Response('<fb:redirect url="%s" />' % url)
            else:
                pylons.helpers.redirect_to(url)

        def check_session(self, request=None, next=""):
            """The request parameter is now optional."""
            if request is None:
                request = pylons.request
            return AbstractFacebook.check_session(self, request, next)

            # The Django request object is similar enough to the Paste
            # request object that check_session and validate_signature
            # should *just work*.


        def apps_url_for(self, *args, **kargs):
            """Like url_for, but starts with "http://apps.facebook.com"."""
            return "http://apps.facebook.com/%s" % url_for(*args, **kargs)


    def pylons_require_login(next=""):
        """Require Facebook login.

        The FacebookWSGIMiddleware must be installed.

        Example::

        @pylons_require_login()  # The parenthesis are mandatory.
        def some_action(self):
            ...

        Of course, you don't have to use this decorator.  You can also
        simply use::

        # Import facebook...
        def some_action(self):
            result = facebook.check_session()
            if result:
                return result
            # Otherwise continue...

        """

        def wrapper(f, *args, **kargs):
            try:
                facebook.check_session
            except AttributeError:
                raise EnvironmentError("""\
pylons.request.facebook was not present.  Have you correctly installed
FacebookWSGIMiddleware into your middleware stack?""")
            result = facebook.check_session(next=next)
            if result:
                return result
            return f(*args, **kargs)

        return decorator(wrapper)


    def create_pylons_facebook_middleware(app, config):
        """This is a simple wrapper for FacebookWSGIMiddleware.

        It passes the correct facebook_class.

        """
        return FacebookWSGIMiddleware(app, config, facebook_class=PylonsFacebook)

