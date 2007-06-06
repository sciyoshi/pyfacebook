from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response

import urllib

import facebook

api_key = ''
secret_key = ''

@facebook.require_login
def canvas(request):
    if not request.facebook.in_canvas:
        return request.facebook.redirect('http://apps.facebook.com/pyfacebook/')

    values = request.facebook.users.getInfo([request.facebook.uid], ['first_name', 'is_app_user', 'has_added_app'])[0]

    name, is_app_user, has_added_app = values['first_name'], values['is_app_user'], values['has_added_app']

    if has_added_app == '0':
        return request.facebook.redirect(request.facebook.get_url('add', api_key=api_key))

    return render_to_response('facebook/canvas.fbml', {'name': name})

@facebook.require_login
def post(request):
    request.facebook.profile.setFBML(request.POST['profile_text'], request.facebook.uid)

    return request.facebook.redirect(request.facebook.get_url('profile', id=request.facebook.uid))

@facebook.require_login
def post_add(request):
    request.facebook.profile.setFBML('Congratulations on adding PyFaceBook. Please click on the PyFaceBook link on the left side to change this text.', request.facebook.uid)

    return request.facebook.redirect('http://apps.facebook.com/pyfacebook/')

@facebook.require_login
def ajax(request):
    return HttpResponse('hello world')
