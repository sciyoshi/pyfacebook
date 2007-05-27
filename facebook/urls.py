from django.conf.urls.defaults import *

urlpatterns = patterns('',
    # This is the canvas callback, i.e. what will be seen
    # when you visit http://apps.facebook.com/<appname>.
    (r'^canvas/', 'facebook.views.canvas'),

    # Extra callbacks can be set in the Facebook app settings
    # page. For example, post_add will be called when a user
    # has added the application.
    (r'^post_add/', 'facebook.views.post_add'),
)
