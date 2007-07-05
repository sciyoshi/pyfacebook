# -----------------------
# Web application example
# -----------------------

def simple_web_app(request, api_key, secret_key):
    fb = Facebook(api_key, secret_key, request.GET['auth_token'])
    fb.auth.getSession()

    friend_ids = fb.friends.get()
    info = fb.users.getInfo(friend_ids, ['name', 'pic'])

    print '<html><body>'
    for friend in info:
        print '<a href="%(pic)s">%(name)s</a>' % friend
    print '</body></html>'

def web_app(request):
    """Get the user's friends and their pictures. This example uses
       the Django web framework, but should be adaptable to others."""

    # Get api_key and secret_key from a file
    fb_file = open('facebook_keys.txt').readlines()
    api_key = fb_file[0].strip()
    secret_key = fb_file[1].strip()
    fb = Facebook(api_key, secret_key)

    # Use the data from the cookie if present
    if 'session_key' in request.session and 'uid' in request.session:
        fb.session_key = request.session['session_key']
        fb.uid = request.session['uid']
    else:
        
        try:
            fb.auth_token = request.GET['auth_token']
        except KeyError:
            # Send user to the Facebook to login
            return HttpResponseRedirect(fb.get_login_url())

        # getSession sets the session_key and uid
        # Store these in the cookie so we don't have to get them again
        fb.auth.getSession()
        request.session['session_key'] = fb.session_key
        request.session['uid'] = fb.uid

    try:
        friend_ids = fb.friends.get()
    except FacebookError, e:
        # Error 102 means the session has expired.
        # Delete the cookie and send the user to Facebook to login
        if e.info['code'] == u'102':
            del request.session['session_key']
            del request.session['uid']
            return HttpResponseRedirect(fb.get_login_url())
        else:
            # Other Facebook errors are possible too. Don't ignore them.
            raise
        
    info = fb.users.getInfo(friend_ids, ['name', 'pic'])
    # info is a list of dictionaries

    # you would never do this in an actual Django application,
    # it's just an example of accessing the results.
    links = []
    for friend in info:
        html = '<a href="%(pic)s">%(name)s</a>' % friend
        links.append(html)

    return render_to_response('template.html', {'links': links})

# ---------------------------
# Desktop application example
# ---------------------------

def desktop_app():
    from facebook import Facebook

    # Get api_key and secret_key from a file
    fbs = open(FB_SETTINGS).readlines()
    facebook = Facebook(fbs[0].strip(), fbs[1].strip())

    facebook.auth.createToken()
    # Show login window
    facebook.login()

    # Login to the window, then press enter
    print 'After logging in, press enter...'
    raw_input()

    facebook.auth.getSession()
    info = facebook.users.getInfo([facebook.uid], ['name', 'birthday', 'affiliations', 'sex'])[0]

    for attr in info:
        print '%s: %s' % (attr, info[attr])

    friends = facebook.friends.get()
    friends = facebook.users.getInfo(friends[0:5], ['name', 'birthday', 'relationship_status'])

    for friend in friends:
        if 'birthday' in friend:
            print friend['name'], 'has a birthday on', friend['birthday'], 'and is', friend['relationship_status']
        else:
            print friend['name'], 'has no birthday and is', friend['relationship_status']

    arefriends = facebook.friends.areFriends([friends[0]['uid']], [friends[1]['uid']])

    photos = facebook.photos.getAlbums(friends[1]['uid'])
    print photos
