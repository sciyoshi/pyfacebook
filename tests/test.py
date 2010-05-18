import unittest
import sys
import os
import facebook
import urllib2
try:
    from hashlib import md5
    md5_constructor = md5
except ImportError:
    import md5
    md5_constructor = md5.new
try:
    import simplejson
except ImportError:
    from django.utils import simplejson
import httplib
from minimock import Mock

my_api_key = "e1e9cfeb5e0d7a52e4fbd5d09e1b873e"
my_secret_key = "1bebae7283f5b79aaf9b851addd55b90"
#'{"error_code":100,\
                 #"error_msg":"Invalid parameter",\
                 #"request_args":[{"key":"format","value":"JSON"},\
                                 #{"key":"auth_token","value":"24626e24bb12919f2f142145070542e8"},\
                                 #{"key":"sig","value":"36af2af3b93da784149301e77cb1621a"},\
                                 #{"key":"v","value":"1.0"},\
                                 #{"key":"api_key","value":"e1e9cfeb5e0d7a52e4fbd5d09e1b873e"},\
                                 #{"key":"method","value":"facebook.auth.getSession"}]}'
response_str = '{"stuff":"abcd"}'
class MyUrlOpen:
    def __init__(self,*args,**kwargs):
        pass
    
    def read(self):
        global response_str
        return response_str
    
class pyfacebook_UnitTests(unittest.TestCase):
    def setUp(self):
        facebook.urllib2.urlopen = Mock('urllib2.urlopen')
        facebook.urllib2.urlopen.mock_returns_func = MyUrlOpen
        pass

    def tearDown(self):
        pass
    
    def login(self):
        pass
                
    def test1(self):
        f = facebook.Facebook(api_key=my_api_key, secret_key=my_secret_key)
        f.login = self.login
        self.assertEquals(f.api_key,my_api_key)
        self.assertEquals(f.secret_key,my_secret_key)
        self.assertEquals(f.auth_token,None)
        self.assertEquals(f.app_name,None)
        self.assertEquals(f.callback_path,None)
        self.assertEquals(f.internal,None)
        
    def test2(self):
        args = {"arg1":"a","arg2":"b","arg3":"c"}
        hasher = md5_constructor(''.join(['%s=%s' % (x, args[x]) for x in sorted(args.keys())]))
        hasher.update("acdnj")
        f = facebook.Facebook(api_key="abcdf", secret_key="acdnj")
        f.login = self.login
        digest = f._hash_args(args)
        self.assertEquals(hasher.hexdigest(),digest)
        hasher = md5_constructor(''.join(['%s=%s' % (x, args[x]) for x in sorted(args.keys())]))
        hasher.update("klmn")
        # trunk code has error hash.updated instead of hash.update
        digest = f._hash_args(args,secret="klmn")
        self.assertEquals(hasher.hexdigest(),digest)
        
        hasher = md5_constructor(''.join(['%s=%s' % (x, args[x]) for x in sorted(args.keys())]))
        f.secret = "klmn"
        hasher.update(f.secret)
        # trunk code has error hash.updated instead of hash.update
        digest = f._hash_args(args)
        self.assertEquals(hasher.hexdigest(),digest)
        
    def test3(self):
        global response_str
        response = {'stuff':'abcd'}
        response_str = simplejson.dumps(response)
        fb = facebook.Facebook(my_api_key, my_secret_key)
        fb.login = self.login
        fb.auth.createToken()
        self.assertEquals(str(fb.auth_token['stuff']),"abcd")
        fb.login()
        response = {"session_key":"key","uid":"my_uid","secret":"my_secret","expires":"my_expires"}
        response_str = simplejson.dumps(response)
        res = fb.auth.getSession()
        self.assertEquals(str(res["expires"]),response["expires"])
        self.assertEquals(str(res["secret"]),response["secret"])
        self.assertEquals(str(res["session_key"]),response["session_key"])
        self.assertEquals(str(res["uid"]),response["uid"])
        
    def test4(self):
        global response_str
        response = 'abcdef'
        response_str = simplejson.dumps(response)
        fb = facebook.Facebook(my_api_key, my_secret_key)
        fb.login = self.login
        fb.auth.createToken()
        self.assertEquals(str(fb.auth_token),"abcdef")
        url = fb.get_login_url(next="nowhere", popup=True, canvas=True)
        self.assertEquals(url,
                          'http://www.facebook.com/login.php?canvas=1&popup=1&auth_token=abcdef&next=nowhere&v=1.0&api_key=%s'%(my_api_key,))
        
    def test5(self):
        class Request:
            def __init__(self,post,get,method):
                self.POST = post
                self.GET = get
                self.method = method
                
        req = Request({'fb_sig_in_canvas':1},{},'POST')
        fb = facebook.Facebook(my_api_key, my_secret_key)
        fb.login = self.login
        res = fb.check_session(req)
        self.assertFalse(res)
        req = Request({'fb_sig':1},{},'POST')
        res = fb.check_session(req)
        self.assertFalse(res)
        req = Request({'fb_sig':fb._hash_args({'in_canvas':'1',
                                               'added':'1',
                                               'expires':'1',
                                               'friends':'joe,mary',
                                               'session_key':'abc',
                                               'user':'bob'}),
                                               'fb_sig_in_canvas':'1',
                                               'fb_sig_added':'1',
                                               'fb_sig_expires':'1',
                                               'fb_sig_friends':'joe,mary',
                                               'fb_sig_session_key':'abc',
                                               'fb_sig_user':'bob'},
                                               {},'POST')
        res = fb.check_session(req)
        self.assertTrue(res)
        fb = facebook.Facebook(my_api_key, my_secret_key)
        fb.login = self.login
        req = Request({'fb_sig':fb._hash_args({'in_canvas':'1',
                                               'added':'1',
                                               'expires':'1',
                                               'friends':'',
                                               'session_key':'abc',
                                               'user':'bob'}),
                                               'fb_sig_in_canvas':'1',
                                               'fb_sig_added':'1',
                                               'fb_sig_expires':'1',
                                               'fb_sig_friends':'',
                                               'fb_sig_session_key':'abc',
                                               'fb_sig_user':'bob'},
                                               {},'POST')
        res = fb.check_session(req)
        self.assertTrue(res)
        fb = facebook.Facebook(my_api_key, my_secret_key)
        fb.login = self.login
        req = Request({'fb_sig':fb._hash_args({'in_canvas':'1',
                                               'added':'1',
                                               'expires':'1',
                                               'friends':'',
                                               'session_key':'abc',
                                               'page_id':'id'}),
                                               'fb_sig_in_canvas':'1',
                                               'fb_sig_added':'1',
                                               'fb_sig_expires':'1',
                                               'fb_sig_friends':'',
                                               'fb_sig_session_key':'abc',
                                               'fb_sig_page_id':'id'},
                                               {},'POST')
        res = fb.check_session(req)
        self.assertTrue(res)
        
    def test6(self):
        global response_str
        response = 'abcdef'
        response_str = simplejson.dumps(response)
        fb = facebook.Facebook(my_api_key, my_secret_key)
        fb.login = self.login
        fb.auth.createToken()
#        self.failUnlessRaises(RuntimeError,fb._add_session_args)
        response = {"session_key":"key","uid":"my_uid","secret":"my_secret","expires":"my_expires"}
        response_str = simplejson.dumps(response)
        fb.auth.getSession()
        args = fb._add_session_args()
        
    def test7(self):
        global response_str
        response = 'abcdef'
        response_str = simplejson.dumps(response)
        fb = facebook.Facebook(my_api_key, my_secret_key)
        fb.login = self.login
        fb.auth.createToken()
        self.assertEquals(str(fb.auth_token),"abcdef")
        url = fb.get_authorize_url(next="next",next_cancel="next_cancel")
        self.assertEquals(url,
                          'http://www.facebook.com/authorize.php?api_key=%s&next_cancel=next_cancel&v=1.0&next=next' % (my_api_key,))
        
    def test8(self):
        class Request:
            def __init__(self,post,get,method):
                self.POST = post
                self.GET = get
                self.method = method
                
        global response_str
        response = {"session_key":"abcdef","uid":"my_uid","secret":"my_secret","expires":"my_expires"}
        response_str = simplejson.dumps(response)
        req = Request({},{'installed':1,'fb_page_id':'id','auth_token':'abcdef'},'GET')
        fb = facebook.Facebook(my_api_key, my_secret_key)
        fb.login = self.login
        res = fb.check_session(req)
        self.assertTrue(res)

    def test9(self):
        global response_str
        response = 'abcdef'
        response_str = simplejson.dumps(response)
        fb = facebook.Facebook(my_api_key, my_secret_key)
        fb.login = self.login
        fb.auth.createToken()
        self.assertEquals(str(fb.auth_token),"abcdef")
        url = fb.get_add_url(next="next")
        self.assertEquals(url,
                          'http://www.facebook.com/install.php?api_key=%s&v=1.0&next=next' % (my_api_key,))

    def send(self,xml):
        self.xml = xml

    def test10(self):
        import Image
        image1 = Image.new("RGB", (400, 300), (255, 255, 255))
        filename = "image_file.jpg"
        image1.save(filename)
        global response_str
        fb = facebook.Facebook(my_api_key, my_secret_key)
        fb.login = self.login
        
        facebook.httplib.HTTP = Mock('httplib.HTTP')
        http_connection = Mock('http_connection')
        facebook.httplib.HTTP.mock_returns = http_connection
        http_connection.send.mock_returns_func = self.send
        def _http_passes():
            return [200,]
        http_connection.getreply.mock_returns_func = _http_passes

        def read():
            response = {"stuff":"stuff"}
            response_str = simplejson.dumps(response)
            return response_str
        http_connection.file.read.mock_returns_func = read
        
        response = {"session_key":"key","uid":"my_uid","secret":"my_secret","expires":"my_expires"}
        response_str = simplejson.dumps(response)
        res = fb.auth.getSession()
        result = fb.photos.upload(image=filename,aid="aid",caption="a caption")
        self.assertEquals(str(result["stuff"]),"stuff")
        os.remove(filename)
        
if __name__ == "__main__":

    # Build the test suite
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(pyfacebook_UnitTests))

    # Execute the test suite
    print("Testing Proxy class\n")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(len(result.errors) + len(result.failures))

