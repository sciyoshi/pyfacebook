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
        return ('Error ' + self.info['error_code'] + ': ' + self.info['error_msg'] + ' (' +
                self.info['request_args']['arg']['value'] + ')')


class Facebook(object):
    def __init__(self, api_key, secret_key, auth_token=None):
        self.api_key = api_key
        self.secret_key = secret_key
        self.secret = None
        self.auth_token = auth_token


    #AUTH
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


    #EVENTS
    def events_get(self, uid, eids, start, end, rsvp_status):
        return self._call_method('facebook.events.get', {
            'uid': uid,
            'eids': eids,
            'start_time': start, 
            'end_time': end,
            'rsvp_status': rsvp_status
            })
    
    def events_getMembers(self, eid):
        return self._call_method('facebook.events.getMembers', {
            'eid': eid
            })


    #FRIENDS
    def friends_get(self):
        return self._call_method('facebook.friends.get')

    def friends_areFriends(self, id1, id2):
        return self._call_method('facebook.friends.areFriends', {
            'uids1': ','.join(id1), 
            'uids2': ','.join(id2)
            })

    def friends_getAppUsers(self, type):
        return self._call_method('facebook.friends.getAppUsers')


    #GROUPS
    def groups_get(self, uid="", gids=[]):
        #int(uid) - Optional - Filter by groups associated with a user with this uid
        #array(gids) - Optional - Filter by this list of group ids
        return self._call_method('facebook.groups.get', {
            'uid': uid,
            'gids': ','.join(gids)
            })
    def groups_getMembers(self, gid):
        return self._call_method('facebook.groups.getmembers', {
            'gid': gid
            })
        
    
    #NOTIFICATIONS
    def notifications_get(self):
        #returns messages, pokes, shares, friend_requests, group_invites, event_invites
        return self._call_method('facebook.notifications.get')
    
    
    #PHOTOS
    def photos_get(self, subj_id="", aid="", pids=[]):
        #int(subj_id) - Optional - Filter by photos associated tagged with this user
        #int(aid) - Optional - Filter by photos in this album
        #array(pids) - Optional - Filter by photos in this list. 
        
        if subj_id=="" and aid=="" and len(pids)==0:
            subj_id=self.uid
        return self._call_method('facebook.photos.get', {
            'subj_id': subj_id,
            'aid': aid,
            'pids': ','.join(pids)
            })
                
    def photos_getAlbums(self, uid="", pids=[]):
        #int(uid) - Optional - Return albums created by this user.
        #array(pids) - Optional - Return albums with aids in this list. 
        return self._call_method('facebook.photos.getAlbums', {
            'uid': uid, 
            'pids': ','.join(pids)
            })
    
    def photos_getTags(self, pids):
        return self._call_method('facebook.photos.getTags', {
            'pids': ','.join(pids)
            })

    #UPDATE
    def update_decodeIDs(self, ids):
        return self._call_method('facebook.update.decodeIDs', {
            'ids':  ','.join(ids) 
            })


    #USERS
    def users_getInfo(self, uids=None, fields=['name']):
        if not uids:
            uids = [self.uid]
        return self._call_method('facebook.users.getInfo', {
            'uids': ','.join(uids), 
            'fields': ','.join(fields)
            })
                
    def users_getLoggedInUser(self):
        return self._call_method('facebook.users.getLoggedInUser')


    #URL FUNCTIONS    
    def get_login_url(self, next=None):
        url = 'http://api.facebook.com/login.php?api_key=' + self.api_key
        url += '&v=1.0'
        if next is not None:
            url += '&next=' + next
        if self.auth_token is not None:
            url += '&auth_token=' + self.auth_token
        return url
    
    def login(self):
        webbrowser.open(self.get_login_url())


    #LINK FUNCTION
    def link(self, link_type='profile', **kwargs):
        return 'http://www.facebook.com/%s.php?%s'%(link_type, urllib.urlencode(kwargs))



    def _parse_response_item(self, node):
        #~ if len(filter(lambda x: x.nodeType == x.ELEMENT_NODE and x.nodeName.endswith('_elt'), node.childNodes)) > 0:
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
        args['v']='1.0' #important for version 1 use

        if method not in ['facebook.auth.createToken', 'facebook.auth.getSession']:
            args['session_key'] = self.session_key
            args['call_id'] = str(int(time() * 1000))

        args['sig'] = self._arg_hash(args)

        if method == 'facebook.auth.getSession':
            xml = urllib2.urlopen('https://api.facebook.com/restserver.php', urllib.urlencode(args)).read()
        else:
            xml = urllib2.urlopen('http://api.facebook.com/restserver.php', urllib.urlencode(args)).read()
        
        dom = parseString(xml)
        result = self._parse_response_item(dom)
        dom.unlink()
        self._check_error(result)
        return result[method[9:].replace(".", "_")+"_response"]


if __name__=="__main__":
    api_key=""
    secret=""
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

    friends = facebook.friends_get()
    friends = facebook.users_getInfo(friends[0:5], ['name', 'birthday', 'relationship_status'])

    for friend in friends:
        print friend['name'], 'has a birthday on', friend['birthday'], 'and is', friend['relationship_status']

    arefriends = facebook.friends_areFriends([friends[0]['uid']], [friends[1]['uid']])
    print arefriends

    photos = facebook.photos_getAlbums(friends[3]['uid'])
    print photos