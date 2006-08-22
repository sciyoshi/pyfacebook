"""
Python bindings for the Facebook API

Copyright (c) 2006 Samuel Cormier-Iijima and Niran Babalola
All rights reserved.

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
import webbrowser
import md5
from time import time
from xml.dom.minidom import parseString



def _get_element_text(elem):
	"""Get a node's text by joining all of the text child nodes."""
	return ''.join(node.data for node in elem.childNodes if node.nodeType == node.TEXT_NODE)


class FacebookError(Exception):
	"""Exception class for errors received from Facebook."""
	def __init__(self, info):
		self.info = info
	def __str__(self):
		return ('Error ' + self.info['code'] + ': ' + self.info['msg'] + ' (' +
				self.info['your_request']['method'] + ')')


class Facebook(object):
	def __init__(self, api_key, secret_key):
		self.api_key = api_key
		self.secret_key = secret_key
		self.secret = None
		self.auth_token = None

	def auth_createToken(self):
		result = self._call_method('facebook.auth.createToken', {})
		self.auth_token = result['token']
		return self.auth_token

	def auth_getSession(self):
		result = self._call_method('facebook.auth.getSession', {'auth_token': self.auth_token})
		self.session_key = result['session_key']
		self.uid = result['uid']
		# don't complain if there isn't a 'secret'. web apps don't have one
		self.secret = result.get('secret')
		return result

	def wall_getCount(self, user=None):
		if not user:
			user = self.uid
		return self._call_method('facebook.wall.getCount', {'id': user})

	def users_getInfo(self, users=None, fields=['name']):
		if not users:
			users = [self.uid]
		return self._call_method('facebook.users.getInfo', {'users': ','.join(users), 'fields': ','.join(fields)})

	def events_getInWindow(self, start, end):
		return self._call_method('facebook.events.getInWindow', {'start_time': str(start), 'end_time': str(end)})

	def pokes_getCount(self):
		return self._call_method('facebook.pokes.getCount', {})

	def photos_getAlbums(self, user=None):
		if not user:
			user = self.uid
		return self._call_method('facebook.photos.getAlbums', {'id': user})

	def photos_getCommentCount(self):
		return self._call_method('facebook.photos.getCommentCount')

	def photos_getFromAlbum(self, album):
		return self._call_method('facebook.photos.getFromAlbum', {'aid': album})

	def messages_getCount(self):
		return self._call_method('facebook.messages.getCount', {})

	def friends_get(self):
		return self._call_method('facebook.friends.get', {})

	def friends_areFriends(self, id1, id2):
		return self._call_method('facebook.friends.areFriends', {'id1': ','.join(id1), 'id2': ','.join(id2)})

	def friends_getTyped(self, type):
		return self._call_method('facebook.friends.getTyped', {'link_type': type})

	def photos_getOfUser(self, user=None, max=20):
		if not user:
			user = self.uid
		return self._call_method('facebook.photos.getOfUser', {'id': user, 'max': str(max)})

	def get_login_url(self):
		url = 'http://api.facebook.com/login.php?api_key=' + self.api_key
		if self.auth_token is not None:
			url += '&auth_token=' + self.auth_token
		return url
	
	def login(self):
		webbrowser.open(self.get_login_url())



	def _parse_response_item(self, node):
		if len(filter(lambda x: x.nodeType == x.ELEMENT_NODE and x.nodeName.endswith('_elt'), node.childNodes)) > 0:
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
		if type(result) is dict and result.has_key('fb_error'):
			raise FacebookError, result['fb_error']
		return True

	def _arg_hash(self, args):
		hash = md5.new()
		hash.update(''.join([key + '=' + args[key] for key in sorted(args.keys())]))
		if self.secret:
			hash.update(self.secret)
		else:
			hash.update(self.secret_key)
		return hash.hexdigest()

	def _call_method(self, method, args={}):
		args['api_key'] = self.api_key
		args['method'] = method

		if method not in ['facebook.auth.createToken', 'facebook.auth.getSession']:
			args['session_key'] = self.session_key
			args['call_id'] = str(int(time() * 1000))

		args['sig'] = self._arg_hash(args)

		if method == 'facebook.auth.getSession':
			xml = urllib2.urlopen('https://api.facebook.com/restserver.php', urllib.urlencode(args)).read()
		else:
			xml = urllib2.urlopen('http://api.facebook.com/restserver.php', urllib.urlencode(args)).read()

		dom = parseString(xml)
		result = self._parse_response_item(dom)['result']
		dom.unlink()
		self._check_error(result)
		return result
