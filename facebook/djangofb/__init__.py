import re
import time
import datetime
import facebook

from django.http import HttpResponse, HttpResponseRedirect
from django.utils.http import urlquote
from django.core.exceptions import ImproperlyConfigured
from django.conf import settings

try:
    from threading import local
except ImportError:
    from django.utils._threading_local import local

__all__ = ['Facebook', 'FacebookMiddleware', 'get_facebook_client', 'require_login', 'require_add']

_thread_locals = local()

class Facebook(facebook.Facebook):
    def redirect(self, url):
        """
        Helper for Django which redirects to another page. If inside a
        canvas page, writes a <fb:redirect> instead to achieve the same effect.

        """
        if self.in_canvas:
            return HttpResponse('<fb:redirect url="%s" />' % (url,))
        elif re.search("^https?:\/\/([^\/]*\.)?facebook\.com(:\d+)?", url.lower()):
            return HttpResponse('<script type="text/javascript">\ntop.location.href = "%s";\n</script>' % url)
        else:
            return HttpResponseRedirect(url)

    def url_for(self, path):
        """
        Expand the path into a full URL, depending on whether we're in a canvas
        page or not.
        
        """
        if self.in_canvas:
            return self.get_app_url(path[1:])
        else:
            return '%s%s' % (settings.SITE_URL, path)

    def _oauth2_process_params(self, request):
        """
        Check a few key parameters for oauth methods
        
        """
        self.in_canvas = (request.REQUEST.get('fb_sig_in_canvas') == '1')
        self.added = (request.REQUEST.get('fb_sig_added') == '1')
        # If app_id is not set explicitly, pick it up from the params
        if not self.app_id:
            self.app_id = request.REQUEST.get('fb_sig_app_id')
        if not self.uid:
            self.uid = request.REQUEST.get('fb_sig_user')

    def oauth2_check_session(self, request):
        """
        Check to see if we have an access_token in our session
        
        """
        valid_token = False

        # See if they're in the request
        if 'session' in request.POST:
            print 'session from POST'
            values = self.validate_oauth_session(request.POST['session'])

        # Might be in the query string (e.g. from iframe)
        elif 'session' in request.GET:
            print 'session from GET'
            values = self.validate_oauth_session(request.GET['session'])

        # Look out for an access_token in our cookies from the JS SDK FB.init
        elif request.COOKIES:
            values = self.validate_oauth_cookie_signature(request.COOKIES)
            print 'session from COOKIE %s' % values

        if values and 'access_token' in values:
            request.session['oauth2_token'] = values['access_token']
            request.session['oauth2_token_expires'] = values['expires']
            self.session_key = values['session_key']
            self.uid = values['uid']
            self.added = True
                    
        # If we've been accepted by the user
        if self.added:
            
            # See if we've got this user's access_token in our session
            if 'oauth2_token' in request.session:
                self.oauth2_token = request.session['oauth2_token']
                self.oauth2_token_expires = request.session['oauth2_token_expires']

            if self.oauth2_token_expires:
                if self.oauth2_token_expires > time.time():
                    # Got a token, and it's valid
                    valid_token = True
                else:
                    del request.session['oauth2_token']
                    del request.session['oauth2_token_expires']
                    
        return valid_token

    def oauth2_check_permissions(self, request, required_permissions,
                                 additional_permissions=None,
                                 fql_check=True, force_check=True):
        """
        Check for specific extended_permissions.
        
        If fql_check is True (default), oauth2_check_session() should be called
        first to ensure the access_token is in place and valid to make query.
        
        """
        has_permissions = False

        req_perms = set(required_permissions.split(','))

        if 'oauth2_extended_permissions' in request.session:
            cached_perms = request.session['oauth2_extended_permissions']

        # so now, fb_sig_ext_perms seems to contain the right perms (!)

        if not force_check and cached_perms and req_perms.issubset(cached_perms):
            # Note that this has the potential to be out of date!
            has_permissions = True
        elif fql_check:
            # TODO allow option to use preload FQL for this?
            perms_query = required_permissions
            
            # Note that we can query additional permissions that we
            # don't require.  This can be useful for optional
            # functionality (or simply for better caching)
            if additional_permissions:
                perms_query += ',' + additional_permissions
                
            perms_results = self.fql.query('select %s from permissions where uid=%s'
                                           % (perms_query, self.uid))[0]
            actual_perms = set()
            for permission, allowed in perms_results.items():
                if allowed == 1:
                    actual_perms.add(permission)
            request.session['oauth2_extended_permissions'] = actual_perms
            has_permissions = req_perms.issubset(actual_perms)

        return has_permissions

    def oauth2_process_code(self, request, redirect_uri):
        """
        Convert the code into an access_token.
        
        """
        if 'code' in request.GET:
            # We've got a code from an authorisation, so convert it to a access_token

            self.oauth2_access_token(request.GET['code'], next=redirect_uri)

            request.session['oauth2_token'] = self.oauth2_token
            request.session['oauth2_token_expires'] = self.oauth2_token_expires

            return True
        # else: 'error_reason' in request.GET
        
        return False


def get_facebook_client():
    """
    Get the current Facebook object for the calling thread.

    """
    try:
        return _thread_locals.facebook
    except AttributeError:
        raise ImproperlyConfigured('Make sure you have the Facebook middleware installed.')



def _check_middleware(request):
    try:
        fb = request.facebook
    except:
        raise ImproperlyConfigured('Make sure you have the Facebook middleware installed.')

    if not fb.oauth2:
        raise ImproperlyConfigured('Please ensure that oauth2 is enabled (e.g. via settings.FACEBOOK_OAUTH2).')
    
    return fb


def require_oauth(redirect_path=None, keep_state=True, in_canvas=True,
                  required_permissions=None, check_permissions=None, force_check=True):
    """
    Decorator for Django views that requires the user to be OAuth 2.0'd.
    The FacebookMiddleware must be installed.
    Note that OAuth 2.0 does away with the app added/logged in distinction -
    it is now the case that users have now either authorised facebook users or
    not, and if they are, they may have granted the app a number of
    extended permissions - there is no lightweight/automatic login any more.

    Standard usage:
        @require_oauth()
        def some_view(request):
            ...
    """
    def decorator(view):
        def newview(request, *args, **kwargs):
            # permissions=newview.permissions

            try:
                fb = _check_middleware(request)
    
                valid_token = fb.oauth2_check_session(request)
    
                if required_permissions:
                    has_permissions = fb.oauth2_check_permissions(
                        request, required_permissions, check_permissions,
                        valid_token, force_check)
                else:
                    has_permissions = True
    
                if not valid_token or not has_permissions:
                    if in_canvas:
                        fb.in_canvas = in_canvas

                    return _redirect_login(request, fb, redirect_path,
                        keep_state, required_permissions)
    
                return view(request, *args, **kwargs)
            except facebook.FacebookError, e:
                # Invalid token (I think this can happen if the user logs out)
                # Unfortunately we don't find this out until we use the api 
                if e.code == 190:
                    del request.session['oauth2_token']
                    del request.session['oauth2_token_expires']
                    return _redirect_login(request, fb, redirect_path,
                        keep_state, required_permissions)
        # newview.permissions = permissions        
        return newview
    return decorator

def _redirect_path(redirect_path, fb, path):
    """
    Resolve the path to use for the redirect_uri for authorization
    
    """
    if not redirect_path and fb.oauth2_redirect:
        redirect_path = fb.oauth2_redirect
    if redirect_path:
        if callable(redirect_path):
            redirect_path = redirect_path(path)
    else:
        redirect_path = path
    return redirect_path

def _redirect_login(request, fb, redirect_path, keep_state, required_permissions):
    """
    Fully resolve the redirect path for an oauth login and add in any state
    info required to bring us back to the correct place afterwards
    """
    redirect_uri = fb.url_for(_redirect_path(redirect_path, fb, request.path))

    if keep_state:
        if callable(keep_state):
            state = keep_state(request)
        else:
            state = request.get_full_path()
        # passing state directly to facebook oauth endpoint doesn't work
        redirect_uri += '?state=%s' % urlquote(state)

    url = fb.get_login_url(next=redirect_uri,
            required_permissions=required_permissions)

    return fb.redirect(url) 


def process_oauth(restore_state=True, in_canvas=True):
    """
    Decorator for Django views that processes the user's code and converts it
    into an access_token.
    The FacebookMiddleware must be installed.

    Standard usage:
        @process_oauth()
        def some_view(request):
            ...
    """
    def decorator(view):
        def newview(request, *args, **kwargs):
            # permissions=newview.permissions

            fb = _check_middleware(request)

            if in_canvas:
                fb.in_canvas = in_canvas

            # Work out what the original redirect_uri value was
            redirect_uri = fb.url_for(_strip_code(request.get_full_path()))

            if fb.oauth2_process_code(request, redirect_uri):
                if restore_state:
                    state = request.GET['state']
                    if callable(restore_state):
                        state = restore_state(state)
                    else:
                        state = fb.url_for(state)
                    return fb.redirect(state)

            return view(request, *args, **kwargs)
        # newview.permissions = permissions        
        return newview
    return decorator


def _strip_code(path):
    """
    Restore the path to the original redirect_uri without the code parameter.
    
    """
    try:
        begin = path.find('&code')
        if begin == -1:
            begin = path.index('?code')
        end = path.find('&', begin+1)
        if end == -1:
            end = len(path)
        return path[:begin] + path[end:]
    except ValueError:
        # no code, probably failed to authenticate
        # TODO strip error_reason instead here?
        return path


def require_login(next=None, internal=None, required_permissions=None):
    """
    Decorator for Django views that requires the user to be logged in.
    The FacebookMiddleware must be installed.

    Standard usage:
        @require_login()
        def some_view(request):
            ...

    Redirecting after login:
        To use the 'next' parameter to redirect to a specific page after login, a callable should
        return a path relative to the Post-add URL. 'next' can also be an integer specifying how many
        parts of request.path to strip to find the relative URL of the canvas page. If 'next' is None,
        settings.callback_path and settings.app_name are checked to redirect to the same page after logging
        in. (This is the default behavior.)
        @require_login(next=some_callable)
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

            if internal is None:
                internal = request.facebook.internal

            if callable(next):
                next = next(request.path)
            elif isinstance(next, int):
                next = '/'.join(request.path.split('/')[next + 1:])
            elif next is None and fb.callback_path and request.path.startswith(fb.callback_path):
                next = request.path[len(fb.callback_path):]
            elif not isinstance(next, str):
                next = ''

            if internal and request.method == 'GET' and fb.app_name:
                next = "%s%s" % (fb.get_app_url(), next)

            try:
                session_check = fb.check_session(request)
            except ValueError:
                session_check = False

            if session_check and required_permissions:
                req_perms = set(required_permissions)
                perms = set(fb.ext_perms)
                has_permissions = req_perms.issubset(perms)
            else:
                has_permissions = True

            if not (session_check and has_permissions):
                #If user has never logged in before, the get_login_url will redirect to the TOS page
                return fb.redirect(
                    fb.get_login_url(next=next,
                        required_permissions=required_permissions)) 

            return view(request, *args, **kwargs)
        newview.next = next
        newview.internal = internal
        return newview
    return decorator


def require_add(next=None, internal=None, on_install=None):
    """
    Decorator for Django views that requires application installation.
    The FacebookMiddleware must be installed.
    
    Standard usage:
        @require_add()
        def some_view(request):
            ...

    Redirecting after installation:
        To use the 'next' parameter to redirect to a specific page after login, a callable should
        return a path relative to the Post-add URL. 'next' can also be an integer specifying how many
        parts of request.path to strip to find the relative URL of the canvas page. If 'next' is None,
        settings.callback_path and settings.app_name are checked to redirect to the same page after logging
        in. (This is the default behavior.)
        @require_add(next=some_callable)
        def some_view(request):
            ...

    Post-install processing:
        Set the on_install parameter to a callable in order to handle special post-install processing.
        The callable should take a request object as the parameter.
        @require_add(on_install=some_callable)
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

            if internal is None:
                internal = request.facebook.internal

            if callable(next):
                next = next(request.path)
            elif isinstance(next, int):
                next = '/'.join(request.path.split('/')[next + 1:])
            elif next is None and fb.callback_path and request.path.startswith(fb.callback_path):
                next = request.path[len(fb.callback_path):]
            else:
                next = ''

            if not fb.check_session(request):
                if fb.added:
                    if request.method == 'GET' and fb.app_name:
                        return fb.redirect('%s%s' % (fb.get_app_url(), next))
                    return fb.redirect(fb.get_login_url(next=next))
                else:
                    return fb.redirect(fb.get_add_url(next=next))

            if not fb.added:
                return fb.redirect(fb.get_add_url(next=next))

            if 'installed' in request.GET and callable(on_install):
                on_install(request)

            if internal and request.method == 'GET' and fb.app_name:
                return fb.redirect('%s%s' % (fb.get_app_url(), next))

            return view(request, *args, **kwargs)
        newview.next = next
        newview.internal = internal
        return newview
    return decorator

# try to preserve the argspecs
try:
    import decorator
except ImportError:
    pass
else:
    # Can this be done with functools.wraps, but maintaining kwargs?
    def updater(f):
        def updated(*args, **kwargs):
            original = f(*args, **kwargs)
            def newdecorator(view):
                return decorator.new_wrapper(original(view), view)
            return decorator.new_wrapper(newdecorator, original)
        return decorator.new_wrapper(updated, f)
    require_oauth = updater(require_oauth)
    process_oauth = updater(process_oauth)
    require_login = updater(require_login)
    require_add = updater(require_add)

class FacebookMiddleware(object):
    """
    Middleware that attaches a Facebook object to every incoming request.
    The Facebook object created can also be accessed from models for the
    current thread by using get_facebook_client().

    callback_path can be a string or a callable.  Using a callable lets us
    pass in something like lambda reverse('our_canvas_view') so we can follow
    the DRY principle.

    """

    def __init__(self, api_key=None, secret_key=None, app_name=None,
                 callback_path=None, internal=None, app_id=None,
                 oauth2=None, oauth2_redirect=None):
        self.api_key = api_key or settings.FACEBOOK_API_KEY
        self.secret_key = secret_key or settings.FACEBOOK_SECRET_KEY
        self.app_name = app_name or getattr(settings, 'FACEBOOK_APP_NAME', None)
        self.callback_path = callback_path or getattr(settings, 'FACEBOOK_CALLBACK_PATH', None)
        self.internal = internal or getattr(settings, 'FACEBOOK_INTERNAL', True)
        self.app_id = app_id or getattr(settings, 'FACEBOOK_APP_ID', None)
        self.oauth2 = oauth2 or getattr(settings, 'FACEBOOK_OAUTH2', False)
        self.oauth2_redirect = oauth2_redirect or getattr(settings, 'FACEBOOK_OAUTH2_REDIRECT', None)
        self.proxy = None
        if getattr(settings, 'USE_HTTP_PROXY', False):
            self.proxy = settings.HTTP_PROXY

    def process_request(self, request):
        callback_path = self.callback_path
        if callable(callback_path):
            callback_path = callback_path()
        _thread_locals.facebook = request.facebook = Facebook(self.api_key,
                self.secret_key, app_name=self.app_name,
                callback_path=callback_path, internal=self.internal,
                proxy=self.proxy, app_id=self.app_id, oauth2=self.oauth2)
        if self.oauth2:
            if self.oauth2_redirect:
                request.facebook.oauth2_redirect = self.oauth2_redirect
            request.facebook._oauth2_process_params(request)
        if not self.internal:
            if 'fb_sig_session_key' in request.GET and ('fb_sig_user' in request.GET or 'fb_sig_canvas_user' in request.GET):
                request.facebook.session_key = request.session['facebook_session_key'] = request.GET['fb_sig_session_key']
                request.facebook.uid = request.session['facebook_user_id'] = request.GET['fb_sig_user'] or request.GET['fb_sig_canvas_user']
            elif int(request.GET.get('fb_sig_added', '1')) and request.session.get('facebook_session_key', None) and request.session.get('facebook_user_id', None):
                request.facebook.session_key = request.session['facebook_session_key']
                request.facebook.uid = request.session['facebook_user_id']

    def process_response(self, request, response):
        
        # Don't assume that request.facebook exists
        # - it's not necessarily true that all process_requests will have been called
        try:
            fb = request.facebook
        except AttributeError:
            return response
        
        if not self.internal and fb.session_key and fb.uid:
            request.session['facebook_session_key'] = fb.session_key
            request.session['facebook_user_id'] = fb.uid

            if fb.session_key_expires:
                expiry = datetime.datetime.utcfromtimestamp(fb.session_key_expires)
                request.session.set_expiry(expiry)

        if not fb.is_session_from_cookie:
            # Make sure the browser accepts our session cookies inside an Iframe
            response['P3P'] = 'CP="NOI DSP COR NID ADMa OPTa OUR NOR"'
            fb_cookies = {
                'expires': fb.session_key_expires,
                'session_key': fb.session_key,
                'user': fb.uid,
            }
            fb_cookies = dict((k, v) for k, v in fb_cookies.items()
                              if v is not None)

            expire_time = None
            if fb.session_key_expires:
                expire_time = datetime.datetime.utcfromtimestamp(fb.session_key_expires)

            for k in fb_cookies:
                response.set_cookie(self.api_key + '_' + k, fb_cookies[k], expires=expire_time)
            if fb_cookies:
                response.set_cookie(self.api_key , fb._hash_args(fb_cookies), expires=expire_time)

        return response
