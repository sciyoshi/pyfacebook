from django.conf.urls.defaults import *

# Hack to get the project name
project = __name__.split('.')[0]

urlpatterns = patterns('',
    # This is the canvas callback, i.e. what will be seen
    # when you visit http://apps.facebook.com/<appname>.
    (r'^canvas/', project + '.facebook.views.canvas'),

    # Extra callbacks can be set in the Facebook app settings
    # page. For example, post_add will be called when a user
    # has added the application.
    (r'^post_add/', project + '.facebook.views.post_add'),
)
