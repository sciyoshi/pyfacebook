from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response

import urllib

from facebook import Facebook

# Fill in your API and secret keys here
api_key = ''
secret_key = ''

def canvas(request):
    # Create a new Facebook object with our keys
    fb = Facebook(api_key, secret_key)

    if request.method == 'POST':
        # Facebook calls us with POST, so validate the signature
        params = fb.validate_signature(request.POST)

        # Error validating, redirect to our site
        if not params or 'session_key' not in params or 'user' not in params:
            if params and params['in_canvas'] == '1':
                return HttpResponse('<fb:redirect url=' + fb.link('tos', api_key=api_key, v='1.0') + ' />')

            return HttpResponseRedirect(fb.link('tos', api_key=api_key, v='1.0'))
    else:
        # We're being viewed outside of Facebook
        if 'auth_token' in request.GET:
            return HttpResponseRedirect('http://apps.facebook.com/pyfacebook/')

        # Request a login
        return HttpResponseRedirect('http://www.facebook.com/login.php?' +
            urllib.urlencode({'v': '1.0', 'api_key': api_key}))

    fb.session_key = params['session_key']
    fb.uid = params['user']

    name = fb.users_getInfo([fb.uid], ['first_name'])[0]['first_name']

    return render_to_response('facebook/canvas.fbml', {'name': name})

def post(request):
    # Create a new Facebook object with our keys
    fb = Facebook(api_key, secret_key)

    if request.method == 'POST':
        # Facebook calls us with POST, so validate the signature
        params = fb.validate_signature(request.POST)

        # Error validating, redirect to our site
        if not params or 'session_key' not in params or 'user' not in params:
            if params and params['in_canvas'] == '1':
                return HttpResponse('<fb:redirect url=' + fb.link('tos', api_key=api_key, v='1.0') + ' />')

            return HttpResponseRedirect(fb.link('tos', api_key=api_key, v='1.0'))
    else:
        # We're being viewed outside of Facebook
        if 'auth_token' in request.GET:
            return HttpResponseRedirect('http://apps.facebook.com/pyfacebook/')

        # Request a login
        return HttpResponseRedirect('http://www.facebook.com/login.php?' +
            urllib.urlencode({'v': '1.0', 'api_key': api_key}))

    fb.session_key = params['session_key']
    fb.uid = params['user']

    fb.profile_setFBML(request.POST['profile_text'], fb.uid)

    return HttpResponseRedirect(fb.link('profile', id=fb.uid))

def post_add(request):
    # Create a new Facebook object with our keys
    fb = Facebook(api_key, secret_key)

    if request.method == 'POST':
        # Facebook calls us with POST, so validate the signature
        params = fb.validate_signature(request.POST)

        # Error validating, redirect to our site
        if not params or 'session_key' not in params or 'user' not in params:
            if params and params['in_canvas'] == '1':
                return HttpResponse('<fb:redirect url=' + fb.link('tos', api_key=api_key, v='1.0') + ' />')

            return HttpResponseRedirect(fb.link('tos', api_key=api_key, v='1.0'))

        return HttpResponseRedirect(fb.link('profile', id=fb.uid))
    else:
        # We're being viewed outside of Facebook
        if 'auth_token' not in request.GET:
            return HttpResponseRedirect('http://www.facebook.com/login.php?' +
                urllib.urlencode({'v': '1.0', 'api_key': api_key}))

        fb = Facebook(api_key, secret_key, request.GET['auth_token'])

        fb.auth_getSession()

        fb.profile_setFBML('Congratulations on adding PyFaceBook. Please click on the PyFaceBook link on the left side to change this text.', fb.uid)

        return HttpResponseRedirect(fb.link('profile', id=fb.uid))

