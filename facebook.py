"""
Python bindings for the Facebook API

Copyright (c) 2006 Samuel Cormier-Iijima and Niran Babalola
All rights reserved.

Updated 2007 for API v1.0 David Edelstein

Thanks to Jason Prado for his Python client to the Facebook API

Thanks to Max Battcher for the proxy idea

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

# we only want to export the Facebook object
__all__ = ['Facebook']

import md5
import sys
import time
import base64
import urllib
import urllib2
import httplib
import mimetypes

# try to use simplejson first, otherwise fallback to XML
try:
    import simplejson
    RESPONSE_FORMAT = 'JSON'
except:
    print 'NOTE: PyFacebook can use simplejson if it is installed, which'
    print 'is much faster than XML and also uses less bandwith. Go to'
    print 'http://undefined.org/python/#simplejson to download it, or do'
    print 'apt-get install python-simplejson on a Debian-like system.'
    print ''
    print 'Falling back to XML...'
    
    from xml.dom import minidom
    RESPONSE_FORMAT = 'XML'

# REST URLs
FACEBOOK_URL = 'http://api.facebook.com/restserver.php'
FACEBOOK_SECURE_URL = 'https://api.facebook.com/restserver.php'

# simple IDL for the Facebook API
METHODS = {
    # feed methods
    'feed': {
        'publishStoryToUser': [
            ('title', str, []),
            ('body', str, ['optional']),
            ('image_1', str, ['optional']),
            ('image_1_link', str, ['optional']),
            ('image_2', str, ['optional']),
            ('image_2_link', str, ['optional']),
            ('image_3', str, ['optional']),
            ('image_3_link', str, ['optional']),
            ('image_4', str, ['optional']),
            ('image_4_link', str, ['optional']),
            ('priority', int, ['optional']),
        ],

        'publishActionOfUser': [
            ('title', str, []),
            ('body', str, ['optional']),
            ('image_1', str, ['optional']),
            ('image_1_link', str, ['optional']),
            ('image_2', str, ['optional']),
            ('image_2_link', str, ['optional']),
            ('image_3', str, ['optional']),
            ('image_3_link', str, ['optional']),
            ('image_4', str, ['optional']),
            ('image_4_link', str, ['optional']),
            ('priority', int, ['optional']),
        ],
    },

    # fql methods
    'fql': {
        'query': [
            ('query', str, []),
        ],
    },

    # friends methods
    'friends': {
        'areFriends': [
            ('uids1', list, []),
            ('uids2', list, []),
        ],

        'get': [],

        'getAppUsers': [],
    },

    'notifications': {
        'send': [
            ('to_ids', list, []),
            ('markup', str, []),
            ('no_email', bool, []),
        ],

        'sendRequest': [
            ('to_ids', list, []),
            ('type', str, []),
            ('content', str, []),
            ('image', str, []),
            ('invite', bool, []),
        ],
    },

    # profile methods
    'profile': {
        'setFBML': [
            ('markup', str, []),
            ('uid', int, ['optional']),
        ],

        'getFBML': [
            ('uid', int, ['optional']),
        ]
    },

    # users methods
    'users': {
        'getInfo': [
            ('uids', list, []),
            ('fields', list, [('default', ['name'])]),
        ],

        'getLoggedInUser': [],

        'isAppAdded': [],
    },

    # events methods
    'events': {
        'get': [
            ('uid', int, ['optional']),
            ('eids', list, ['optional']),
            ('start_time', int, ['optional']),
            ('end_time', int, ['optional']),
            ('rsvp_status', str, ['optional']),
        ],

        'getMembers': [
            ('eid', int, []),
        ],
    },

    # update methods
    'update': {
        'decodeIDs': [
            ('ids', list, []),
        ],
    },

    # groups methods
    'groups': {
        'get': [
            ('uid', int, ['optional']),
            ('gids', list, ['optional']),
        ],

        'getMembers': [
            ('gid', int, [])
        ],
    },

    # photos methods
    'photos': {
        'addTag': [
            ('pid', int, []),
            ('tag_uid', int, [('default', 0)]),
            ('tag_text', str, [('default', '')]),
            ('x', float, [('default', 50)]),
            ('y', float, [('default', 50)]),
            ('tags', str, ['optional']),
        ],

        'createAlbum': [
            ('name', str, []),
            ('location', str, ['optional']),
            ('description', str, ['optional']),
        ],

        'get': [
            ('subj_id', int, ['optional']),
            ('aid', int, ['optional']),
            ('pids', list, ['optional']),
        ],

        'getAlbums': [
            ('uid', int, ['optional']),
            ('pids', list, ['optional']),
        ],

        'getTags': [
            ('pids', list, []),
        ],
    },

    # fbml methods
    'fbml': {
        'refreshImgSrc': [
            ('url', str, []),
        ],

        'refreshRefUrl': [
            ('url', str, []),
        ],
    },
}


def _get_element_text(elem):
    """Get a node's text by joining all of the text child nodes."""
    return ''.join(node.data for node in elem.childNodes if node.nodeType == node.TEXT_NODE)


class Proxy(object):
    """Represents a "namespace" of Facebook API calls."""

    def __init__(self, client, name):
        self._client = client
        self._name = name

    def __call__(self, method, args=None):
        if not self._client.session_key:
            raise RuntimeError('Session key not set. Make sure auth.getSession has been called.')

        args['session_key'] = self._client.session_key
        args['call_id'] = str(int(time.time()) * 1000)

        return self._client('%s.%s' % (self._name, method), args)

# generate the Facebook proxies
def __generate_proxies():
    for namespace in METHODS:
        methods = {}
        
        for method in METHODS[namespace]:
            params = ['self']
            body = ['args = {}']
            
            for param_name, param_type, param_options in METHODS[namespace][method]:
                param = param_name
            
                for option in param_options:
                    if isinstance(option, tuple) and option[0] == 'default':
                        if param_type == list:
                            param = '%s=None' % param_name
                            body.append('if %s is None: %s = %s' % (param_name, param_name, repr(option[1])))
                        else:
                            param = '%s=%s' % (param_name, repr(option[1]))
                
                if 'optional' in param_options:
                    param = '%s=None' % param_name
                    body.append('if %s is not None: args[\'%s\'] = %s' % (param_name, param_name, param_name))
                else:
                    body.append('args[\'%s\'] = %s' % (param_name, param_name))
                
                params.append(param)
            
            body.insert(0, 'def %s(%s):' % (method, ', '.join(params)))
            
            body.append('return self(\'%s\', args)' % method)
            
            exec('\n    '.join(body))
            
            methods[method] = eval(method)
            
        proxy = type('%sProxy' % namespace.title(), (Proxy, ), methods)
        
        globals()[proxy.__name__] = proxy

__generate_proxies()

class FacebookError(Exception):
    """Exception class for errors received from Facebook."""

    def __init__(self, code, msg, args=None):
        self.code = code
        self.msg = msg
        self.args = args

    def __str__(self):
        return 'Error %s: %s' % (self.code, self.msg)

class AuthProxy(Proxy):
    """Special proxy for facebook.auth."""

    def getSession(self):
        args = {}
        args['auth_token'] = self._client.auth_token
        result = self._client('%s.getSession' % self._name, args)
        self._client.session_key = result['session_key']
        self._client.uid = result['uid']
        self._client.secret = result.get('secret')
        return result

    def createToken(self):
        result = self._client('%s.createToken' % self._name)
        self._client.auth_token = result
        return self._client.auth_token

# inherit from ourselves!
class PhotosProxy(PhotosProxy):
    """Special proxy for facebook.photos."""

    def upload(self, image, aid=None, caption=None):
        args = {}
        
        if aid is not None:
            args['aid'] = aid

        if caption is not None:
            args['caption'] = caption

        args['api_key'] = self._client.api_key
        args['method'] = 'facebook.photos.upload'
        args['v'] = '1.0'

        args['session_key'] = self._client.session_key
        args['call_id'] = str(int(time.time() * 1000))

        args['format'] = RESPONSE_FORMAT

        args['sig'] = self._client._hash_args(args)

        content_type, body = self.__encode_multipart_formdata(list(args.iteritems()), [(image, file(image).read())])
        h = httplib.HTTP('api.facebook.com')
        h.putrequest('POST', '/restserver.php')
        h.putheader('content-type', content_type)
        h.putheader('content-length', str(len(body)))
        h.endheaders()
        h.send(body)

        response = h.file.read()

        if RESPONSE_FORMAT == 'JSON':
            result = simplejson.loads(response)
            
            self._client._check_error(result)
        else:
            dom = minidom.parseString(response)
            result = self._client._parse_response_item(dom)
            dom.unlink()

            if 'error_response' in result:
                self._client._check_error(result['error_response'])

            result = result['photos_upload_response']

        return result


    def __encode_multipart_formdata(self, fields, files):
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
            l.append('Content-Type: %s' % self.__get_content_type(filename))
            l.append('')
            l.append(base64.b64encode(value))
        l.append('--' + boundary + '--')
        l.append('')
        body = crlf.join(l)
        content_type = 'multipart/form-data; boundary=%s' % boundary
        return content_type, body


    def __get_content_type(self, filename):
        return mimetypes.guess_type(filename)[0] or 'application/octet-stream'
	    


class Facebook(object):
    """Provides access to the Facebook API."""

    def __init__(self, api_key, secret_key):
        self.api_key = api_key
        self.secret_key = secret_key
        self.session_key = None
        self.auth_token = None
        self.secret = None
        self.in_canvas = False
        
        for namespace in METHODS:
            self.__dict__[namespace] = eval('%sProxy(self, \'%s\')' % (namespace.title(), 'facebook.%s' % namespace))
        
        self.auth = AuthProxy(self, 'facebook.auth')


    def _hash_args(self, args):
        hasher = md5.new(''.join(['%s=%s' % (x, args[x]) for x in sorted(args.keys())]))
        if self.secret:
            hasher.update(self.secret)
        else:
            hasher.update(self.secret_key)
        return hasher.hexdigest()


    def _parse_response_item(self, node):
        if node.nodeType == node.DOCUMENT_NODE and \
            node.childNodes[0].hasAttributes() and \
            node.childNodes[0].hasAttribute('list') and \
            node.childNodes[0].getAttribute('list') == "true":
            return {node.childNodes[0].nodeName: self._parse_response_list(node.childNodes[0])}
        elif node.nodeType == node.ELEMENT_NODE and \
            node.hasAttributes() and \
            node.hasAttribute('list') and \
            node.getAttribute('list')=="True":
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


    def _check_error(self, response):
        if type(response) is dict and response.has_key('error_code'):
            print (response['error_code'], response['error_msg'], response['request_args'])
            raise FacebookError(response['error_code'], response['error_msg'], response['request_args'])


    def __call__(self, method, args=None, secure=False):
        if args is None:
            args = {}
        
        for arg in args.items():
            if type(arg[1]) == list:
                args[arg[0]] = ','.join(arg[1])
        
        args['method'] = method
        args['api_key'] = self.api_key
        args['v'] = '1.0'
        args['format'] = RESPONSE_FORMAT
        args['sig'] = self._hash_args(args)
        
        post_data = urllib.urlencode(args)
        
        if secure:
            response = urllib2.urlopen(FACEBOOK_SECURE_URL, urllib.urlencode(args)).read()
        else:
            response = urllib2.urlopen(FACEBOOK_URL, urllib.urlencode(args)).read()
        
        
        if RESPONSE_FORMAT == 'JSON':
            result = simplejson.loads(response)
            
            self._check_error(result)
        else:
            dom = minidom.parseString(response)
            result = self._parse_response_item(dom)
            dom.unlink()

            if 'error_response' in result:
                self._check_error(result['error_response'])

            result = result[method[9:].replace('.', '_') + '_response']

        return result


    # URL helpers
    def get_url(self, page, **args):
        return 'http://www.facebook.com/%s.php?%s' % (page, urllib.urlencode(args))

    def get_login_url(self, next=None):
        args = {'api_key': self.api_key, 'v': '1.0'}
        
        if next is not None:
            args['next'] = next
        
        if self.auth_token is not None:
            args['auth_token'] = self.auth_token
        
        return 'http://www.facebook.com/login.php?%s' % urllib.urlencode(args)

    def login(self):
        import webbrowser
        webbrowser.open(self.get_login_url())


    # Django helpers
    def redirect(self, url):
        from django.http import HttpResponse, HttpResponseRedirect

        if self.in_canvas:
            return HttpResponse('<fb:redirect url="%s" />' % (url, ))
        else:
            return HttpResponseRedirect(url)

    def check_session(self, request, next=''):
        if request.method == 'POST':
            self.params = self.validate_signature(request.POST)

            if 'fb_sig_in_canvas' in request.POST and request.POST['fb_sig_in_canvas'] == '1':
                self.in_canvas = True

            if not self.params or 'session_key' not in self.params or 'user' not in self.params:
                return self.redirect(self.get_url('tos', api_key=self.api_key, v='1.0', next=next))

            self.session_key = self.params['session_key']
            self.uid = self.params['user']

            if 'in_canvas' in self.params:
                self.in_canvas = self.params['in_canvas'] == '1'

        else:
            if 'auth_token' in request.GET:
                self.auth_token = request.GET['auth_token']

                try:
                    self.auth.getSession()
                except:
                    self.auth_token = None

                    return self.redirect(self.get_login_url(next=next))

            else:
                return self.redirect(self.get_login_url(next=next))

    def validate_signature(self, post, prefix='fb_sig', timeout=None):
        """
        Validate parameters passed to an internal Facebook app from Facebook.
        """
        args = post.copy()
        del args[prefix]

        if timeout and '%s_time' % prefix in post and time.time() - float(post['%s_time' % prefix]) > timeout:
            return None

        args = dict([(key[len(prefix + '_'):], value) for key, value in args.items() if key.startswith(prefix)])

        hash = self._hash_args(args)

        if hash == post[prefix]:
            return args
        else:
            return None

try:
    from django.core.exceptions import ImproperlyConfigured
    from django.conf import settings

    def require_login(view, next=''):
        def newview(request, *args, **kwargs):
            try:
                fb = request.facebook
            except:
                raise ImproperlyConfigured('Make sure you have the Facebook middleware installed.')

            result = fb.check_session(request, next)

            if result:
                return result

            return view(request, *args, **kwargs)

        return newview

    class FacebookMiddleware(object):
        def __init__(self, api_key=None, secret_key=None):
            self.api_key = api_key or settings.FACEBOOK_API_KEY
            self.secret_key = secret_key or settings.FACEBOOK_SECRET_KEY

        def process_request(self, request):
            request.facebook = Facebook(self.api_key, self.secret_key)

except:
    pass


if __name__ == '__main__':
    # sample desktop application

    api_key = ''
    secret_key = ''
    
    facebook = Facebook(api_key, secret_key)

    facebook.auth.createToken()
    # Show login window
    facebook.login()

    # Login to the window, then press enter
    print 'After logging in, press enter...'
    raw_input()

    facebook.auth.getSession()
    print 'Session Key:   ', facebook.session_key
    print 'Your UID:      ', facebook.uid
    
    info = facebook.users.getInfo([facebook.uid], ['name', 'birthday', 'affiliations', 'sex'])[0]
    
    print 'Your Name:     ', info['name']
    print 'Your Birthday: ', info['birthday']
    print 'Your Gender:   ', info['sex']

    friends = facebook.friends.get()
    friends = facebook.users.getInfo(friends[0:5], ['name', 'birthday', 'relationship_status'])

    for friend in friends:
        print friend['name'], 'has a birthday on', friend['birthday'], 'and is', friend['relationship_status']

    arefriends = facebook.friends.areFriends([friends[0]['uid']], [friends[1]['uid']])
 
    photos = facebook.photos.getAlbums(facebook.uid)
 
