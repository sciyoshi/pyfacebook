"""
Python bindings for the Facebook API

Copyright (c) 2006 Samuel Cormier-Iijima and Niran Babalola
All rights reserved.

updated 2007 for APIv1.0 David Edelstein

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import urllib
import urllib2
import httplib
import mimetypes
import webbrowser
import md5
import base64
import time
import cgi

from time import time
from xml.dom.minidom import parseString



def _get_element_text(elem):
    """Get a node's text by joining all of the text child nodes."""
    return ''.join(node.data for node in elem.childNodes if node.nodeType == node.TEXT_NODE)


class FacebookError(Exception):
    """Exception class for errors received from Facebook."""
    def __init__(self, info):
        self.info = info
    
    def __repr__(self):
        return str(self)
    
    def __str__(self):
        return 'Error %s: %s (%s)' % (
            self.info['error_code'],
            self.info['error_msg'],
            ', '.join(
               '%s = %s' % (arg['key'], arg['value']) for arg in self.info['request_args'].values()))


class Facebook(object):
    _special_methods = ['auth.createToken', 'auth.getSession', 'photos.upload']

    _methods = {
        # AUTH methods
        'auth.createToken': [],
        'auth.getSession': [],
        
        # FQL methods
        'fql.query':
        [
            ('query', str, []),
        ],
        
        # EVENTS methods
        'events.get':
        [
            ('uid', int, ['optional']),
            ('eids', list, ['optional']),
            ('start_time', int, ['optional']),
            ('end_time', int, ['optional']),
            ('rsvp_status', str, ['optional']),
        ],
        
        'events.getMembers':
        [
            ('eid', int, []),
        ],
        
        # FRIENDS methods
        'friends.areFriends':
        [
            ('uids1', list, []),
            ('uids2', list, []),
        ],
        
        'friends.get': [],
        
        'friends.getAppUsers': [],
        
        # GROUPS methods
        'groups.get':
        [
            ('uid', int, ['optional']),
            ('gids', list, ['optional']),
        ],
        
        'groups.getMembers':
        [
            ('gid', int, [])
        ],
        
        # NOTIFICATIONS methods
        'notifications.get': [],

        'notifications.send':
        [
            ('to_ids', list, []),
            ('markup', str, []),
            ('no_email', bool, []),
        ],

        'notifications.sendRequest':
        [
            ('to_ids', list, []),
            ('type', str, []),
            ('content', str, []),
            ('image', str, []),
            ('invite', bool, []),
        ],

        # PROFILE methods
        'profile.setFBML':
        [
            ('markup', str, []),
            ('uid', int, ['optional']),
        ],

        'fbml.refreshImgSrc':
        [
            ('url', str, []),
        ],

        'fbml.refreshRefUrl':
        [
            ('url', str, []),
        ],

        # PHOTOS methods
        'photos.addTag':
        [
            ('pid', int, []),
            ('tag_uid', int, [('default', 0)]),
            ('tag_text', str, [('default', '')]),
            ('x', float, [('default', 50)]),
            ('y', float, [('default', 50)]),
            ('tags', str, ['optional']),
        ],
        
        'photos.createAlbum':
        [
            ('name', str, []),
            ('location', str, ['optional']),
            ('description', str, ['optional']),
        ],
        
        'photos.get':
        [
            ('subj_id', int, ['optional']),
            ('aid', int, ['optional']),
            ('pids', list, ['optional']),
        ],
        
        'photos.getAlbums':
        [
            ('uid', int, ['optional']),
            ('pids', list, ['optional']),
        ],
        
        'photos.getTags':
        [
            ('pids', list, []),
        ],
        
        'photos.upload':
        [
            ('aid', int, ['optional']),
            ('caption', str, ['optional']),
            ('', None, []),
        ],
        
        # UPDATE methods
        'update.decodeIDs':
        [
            ('ids', list, []),
        ],
        
        # USERS methods
        'users.getInfo':
        [
            ('uids', list, []),
            ('fields', list, [('default', ['name'])]),
        ],
        
        'users.getLoggedInUser': [],

        'users.isAppAdded': [],
    }
    
    def __init__(self, api_key, secret_key, auth_token=None):
        self.api_key = api_key
        self.secret_key = secret_key
        self.secret = None
        self.in_canvas = False
        self.auth_token = auth_token

    for method_name in sorted(_methods.keys()):
        if method_name in _special_methods:
            continue
        
        signature = 'def ' + method_name.replace('.', '_') + '(self'
        
        indent1 = '\n'
        indent2 = indent1 + '    '
        indent3 = indent2 + '    '
        
        body = ''
        
        for param_name, param_type, param_options in _methods[method_name]:
            signature += ', ' + param_name
            
            for option in param_options:
                # Check for defaults:
                if isinstance(option, tuple):
                    if option[0] == 'default':
                        if param_type == list:
                            signature += '=None'
                            body += indent2 + 'if ' + param_name + ' == None:'
                            body += indent3 + param_name + ' = ' + repr(option[1])
                        else:
                            signature += '=' + repr(option[1])
                            
            if 'optional' in param_options:
                signature += '=None'
                body += indent2 + 'if ' + param_name + ' is not None:'
                body += indent3 + 'params["' + param_name + '"] = ' + param_name 
            else:
                body += indent2 + 'params["' + param_name + '"] = ' + param_name

        signature += '):'

        body += indent2 + 'return self._call_method("facebook.' + method_name + '"'
        
        if _methods[method_name] != []:
            body = indent2 + 'params = {}' + body
            body += ', params'

        body += ')'

        definition = signature + body

        exec definition

    # AUTH methods
    def auth_createToken(self):
        result = self._call_method('facebook.auth.createToken')
        self.auth_token = result
        return self.auth_token

    def auth_getSession(self):
        result = self._call_method('facebook.auth.getSession', {
            'auth_token': self.auth_token
                })
        self.session_key = result['session_key']
        self.uid = result['uid']
        # don't complain if there isn't a 'secret'. web apps don't have one
        self.secret = result.get('secret')
        return result

    def photos_upload(self, image, aid=None, caption=None):
        args = {}
        
        if aid is not None:
            args['aid'] = aid

        if caption is not None:
            args['caption'] = caption

        args['api_key'] = self.api_key
        args['method'] = 'facebook.photos.upload'
        args['v'] = '1.0'

        args['session_key'] = self.session_key
        args['call_id'] = str(int(time() * 1000))

        args['sig'] = self.arg_hash(args)

        content_type, body = self._encode_multipart_formdata(list(args.iteritems()), [(image, file(image).read())])
        h = httplib.HTTP('api.facebook.com')
        h.putrequest('POST', '/restserver.php')
        h.putheader('content-type', content_type)
        h.putheader('content-length', str(len(body)))
        h.endheaders()
        h.send(body)
        print h.getreply()
        dom = parseString(h.file.read())
        result = self._parse_response_item(dom)
        dom.unlink()
        self._check_error(result)
        return result['photos_upload_response']
    	
    def _encode_multipart_formdata(self, fields, files):
        boundary = '----------ThIs_Is_tHe_bouNdaRY_$'
        crlf = '\r\n'
        l = []
        
        for (key, value) in fields:
            l.append('--' + boundary)
            l.append('Content-Disposition: form-data; name="%s"' % key)
            l.append('')
            l.append(value)
        for (filename, value) in files:
            l.append('--' + boundary)
            l.append('Content-Disposition: form-data; filename="%s"' % (filename, ))
            l.append('Content-Transfer-Encoding: base64')
            l.append('Content-Type: %s' % self._get_content_type(filename))
            l.append('')
            l.append(base64.b64encode(value))
        l.append('--' + boundary + '--')
        l.append('')
        body = crlf.join(l)
        content_type = 'multipart/form-data; boundary=%s' % boundary
        return content_type, body

    def _get_content_type(self, filename):
        return mimetypes.guess_type(filename)[0] or 'application/octet-stream'
	    
    # URL methods    
    def get_login_url(self, next=None):
        url = 'http://api.facebook.com/login.php?api_key=' + self.api_key
        url += '&v=1.0'
        if next is not None:
            url += '&next=' + next
        if self.auth_token is not None:
            url += '&auth_token=' + self.auth_token
        return url

    def get_app_url(self, appname):
        return 'http://apps.facebook.com/%s/' % appname
    
    def login(self):
        webbrowser.open(self.get_login_url())


    # LINK method
    def link(self, link_type='profile', **kwargs):
        return 'http://www.facebook.com/%s.php?%s' % (link_type, urllib.urlencode(kwargs))


    def redirect(self, url):
        from django.http import HttpResponse, HttpResponseRedirect

        if self.in_canvas:
            return HttpResponse('<fb:redirect url="%s" />' % (url, ))
        else:
            return HttpResponseRedirect(url)


    def check_session(self, request, next=''):
        from django.http import HttpResponse, HttpResponseRedirect

        if request.method == 'POST':
            self.params = self.validate_signature(request.POST)

            if 'fb_sig_in_canvas' in request.POST and request.POST['fb_sig_in_canvas'] == '1':
                self.in_canvas = True

            if not self.params or 'session_key' not in self.params or 'user' not in self.params:
                return self.redirect(self.link('tos', api_key=self.api_key, v='1.0', next=next))

            self.session_key = self.params['session_key']
            self.uid = self.params['user']

            if 'in_canvas' in self.params:
                self.in_canvas = self.params['in_canvas'] == '1'

        else:
            if 'auth_token' in request.GET:
                self.auth_token = request.GET['auth_token']

                try:
                    self.auth_getSession()
                except:
                    return self.redirect(self.get_login_url(next=next))

            else:
                return self.redirect(self.get_login_url(next=next))

    def validate_signature(self, post, prefix='fb_sig', timeout=None):
        '''
        Validate POST parameters passed to an internal Facebook app from Facebook.
        '''
        args = post.copy()
        del args[prefix]

        if timeout and prefix + '_time' in post and time.time() - float(post[prefix + '_time']) > timeout:
            return None

        args = dict([(key[len(prefix + '_'):], value) for key, value in args.items() if key.startswith(prefix)])

        hash = self.arg_hash(args)

        if hash == post[prefix]:
            return args
        else:
            return None

    def _parse_response_item(self, node):
        if node.nodeType==node.DOCUMENT_NODE and node.childNodes[0].hasAttributes() and node.childNodes[0].hasAttribute('list') and node.childNodes[0].getAttribute('list')=="true":
            return {node.childNodes[0].nodeName: self._parse_response_list(node.childNodes[0])}
        elif node.nodeType==node.ELEMENT_NODE and node.hasAttributes() and node.hasAttribute('list') and node.getAttribute('list')=="True":
            return self._parse_response_list(node)
        elif len(filter(lambda x: x.nodeType == x.ELEMENT_NODE, node.childNodes)) > 0:
            return self._parse_response_dict(node)
        else:
            return _get_element_text(node)

    def _parse_response_dict(self, node):
        result = {}
        for item in filter(lambda x: x.nodeType == x.ELEMENT_NODE, node.childNodes):
            result[item.nodeName] = self._parse_response_item(item)
        if node.nodeType == node.ELEMENT_NODE and node.hasAttributes():
            if node.hasAttribute('id'):
                result['id'] = node.getAttribute('id')
        return result

    def _parse_response_list(self, node):
        result = []
        for item in filter(lambda x: x.nodeType == x.ELEMENT_NODE, node.childNodes):
            result.append(self._parse_response_item(item))
        return result
        

    def _check_error(self, result):
        if type(result) is dict and result.has_key('error_response'):
            raise FacebookError, result['error_response']
        return True

    def arg_hash(self, args):
        hash = md5.new()
        hash.update(''.join([key + '=' + args[key] for key in sorted(args.keys())]))
        if self.secret:
            hash.update(self.secret)
        else:
            hash.update(self.secret_key)
        return hash.hexdigest()

    def _call_method(self, method, args=None):
        if args == None:
            args = {}
    
        for key in args.keys():
            if isinstance(args[key], list):
                args[key] = ','.join(args[key])

        args['api_key'] = self.api_key
        args['method'] = method
        args['v'] = '1.0'

        if method not in ['facebook.auth.createToken', 'facebook.auth.getSession']:
            args['session_key'] = self.session_key
            args['call_id'] = str(int(time() * 1000))

        args['sig'] = self.arg_hash(args)

        if method == 'facebook.auth.getSession':
            xml = urllib2.urlopen('https://api.facebook.com/restserver.php', urllib.urlencode(args)).read()
        else:
            xml = urllib2.urlopen('http://api.facebook.com/restserver.php', urllib.urlencode(args)).read()
        
        dom = parseString(xml)
        result = self._parse_response_item(dom)
        dom.unlink()
        self._check_error(result)
        return result[method[9:].replace('.', '_') + '_response']


if __name__=="__main__":
    api_key = ""
    secret = ""
    facebook = Facebook(api_key, secret)
    
    facebook.auth_createToken()
    # Show login window
    facebook.login()

    # Login to the window, then press enter
    print 'After logging in, press enter...'
    raw_input()

    facebook.auth_getSession()
    print 'Session Key: ', facebook.session_key
    print 'uid: ', facebook.uid
    
    info = facebook.users_getInfo([facebook.uid], ['name', 'birthday', 'affiliations', 'sex'])[0]

    print 'Name: ', info['name']
    print 'ID: ', facebook.uid
    print 'Birthday: ', info['birthday']
    print 'Gender: ', info['sex']

    for thing in facebook.fql_query(
        'SELECT concat(first_name, " ", last_name, ": ", birthday) FROM user \
         WHERE uid IN (SELECT uid2 FROM friend WHERE uid1=' + facebook.uid + ') AND strlen(last_name) = 7'):
         print thing['anon']

    print facebook.photos_upload('Vista.jpg')

    friends = facebook.friends_get()
    friends = facebook.users_getInfo(friends[0:5], ['name', 'birthday', 'relationship_status'])

    for friend in friends:
        print friend['name'], 'has a birthday on', friend['birthday'], 'and is', friend['relationship_status']

    arefriends = facebook.friends_areFriends([friends[0]['uid']], [friends[1]['uid']])
    print arefriends

    photos = facebook.photos_getAlbums(facebook.uid)
    print photos
