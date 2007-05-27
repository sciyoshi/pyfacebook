from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response

import urllib

from facebook import Facebook

api_key = '4caee2449ac74758ff8e49064c5770bb'
secret_key = '1698edd7ec096affe0928d071f3d1a22'

def canvas(request):
    # Create a new Facebook object with our keys
    fb = Facebook(api_key, secret_key)

    if request.method == 'POST':
        # Facebook calls us with POST, so validate the signature
        params = fb.validate_signature(request.POST)

        # Error validating, redirect to our site
        if not params:
            return HttpResponseRedirect('http://server02.boknow.com/pyfacebook_sample/facebook/canvas/')
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
        if not params:
            return HttpResponseRedirect('http://server02.boknow.com/pyfacebook_sample/facebook/canvas/')
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
        if not params:
            return HttpResponseRedirect('http://server02.boknow.com/pyfacebook_sample/facebook/canvas/')
    else:
        # We're being viewed outside of Facebook
        if 'auth_token' in request.GET:
            return HttpResponseRedirect('http://apps.facebook.com/pyfacebook/')

        # Request a login
        return HttpResponseRedirect('http://www.facebook.com/login.php?' +
            urllib.urlencode({'v': '1.0', 'api_key': api_key}))

    fb.session_key = params['session_key']
    fb.uid = params['user']

    fb.profile_setFBML('Congratulations on adding PyFaceBook. Please click on the PyFaceBook link on the left side to change this text.', fb.uid)

    return HttpResponseRedirect(fb.link('profile', id=fb.uid))

