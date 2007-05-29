from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response

import urllib

from facebook import Facebook

api_key = ''
secret_key = ''

def canvas(request):
    # Create a new Facebook object with our keys
    fb = Facebook(api_key, secret_key)

    result = fb.check_session(request)

    if result:
        return result

    if not fb.in_canvas:
        return fb.redirect(fb.get_app_url('pyfacebook'))

    values = fb.users_getInfo([fb.uid], ['first_name', 'is_app_user', 'has_added_app'])[0]

    name, is_app_user, has_added_app = values['first_name'], values['is_app_user'], values['has_added_app']

    if has_added_app == '0':
        return fb.redirect(fb.link('add', v='1.0', api_key=api_key))

    return render_to_response('facebook/canvas.fbml', {'name': name})

def post(request):
    # Create a new Facebook object with our keys
    fb = Facebook(api_key, secret_key)

    result = fb.check_session(request)

    if result:
        return result

    fb.profile_setFBML(request.POST['profile_text'], fb.uid)

    return fb.redirect(fb.link('profile', id=fb.uid))

def post_add(request):
    # Create a new Facebook object with our keys
    fb = Facebook(api_key, secret_key)

    result = fb.check_session(request)

    if result:
        return result

    fb.profile_setFBML('Congratulations on adding PyFaceBook. Please click on the PyFaceBook link on the left side to change this text.', fb.uid)

    return fb.redirect(fb.get_app_url('pyfacebook'))

