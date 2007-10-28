#!/usr/bin/env python

if __name__ == '__main__':
    import sys, os, re

    def usage():
        sys.stderr.write('Usage: djangofb.py startapp <appname>\n')
        sys.exit(1)

    if len(sys.argv) not in (2, 3):
        usage()

    if sys.argv[1] != 'startapp':
        usage()

    app_name = len(sys.argv) == 3 and sys.argv[2] or 'fbapp'

    try:
        sys.path.insert(0, os.getcwd())
        import settings # Assumed to be in the same directory or current directory.
    except ImportError:
        sys.stderr.write("Error: Can't find the file 'settings.py' in the directory containing %r or in the current directory. It appears you've customized things.\nYou'll have to run django-admin.py, passing it your settings module.\n(If the file settings.py does indeed exist, it's causing an ImportError somehow.)\n" % __file__)
        sys.exit(1)

    from django.core import management

    directory = management.setup_environ(settings)

    if hasattr(management, 'color'):
        # Current svn version of django
        from django.core.management.color import color_style
        style = color_style()
    else:
        # Compatibility with 0.96
        from django.core.management import style

    project_dir = os.path.normpath(os.path.join(directory, '..'))
    parent_dir = os.path.basename(project_dir)
    project_name = os.path.basename(directory)
    if app_name == project_name:
        sys.stderr.write(style.ERROR('Error: You cannot create an app with the same name (%r) as your project.\n' % app_name))
        sys.exit(1)
    if app_name == 'facebook':
        sys.stderr.write(style.ERROR('Error: You cannot name your app "facebook", since this can cause conflicts with imports in Python < 2.5.\n'))
        sys.exit(1)
    if not re.search(r'^\w+$', app_name):
        sys.stderr.write(style.ERROR('Error: %r is not a valid app name. Please use only numbers, letters and underscores.\n' % (app_name)))
        sys.exit(1)

    top_dir = os.path.join(directory, app_name)
    try:
        os.mkdir(top_dir)
    except OSError, e:
        sys.stderr.write(style.ERROR("Error: %s\n" % e))
        sys.exit(1)

    import facebook

    template_dir = os.path.join(facebook.__path__[0], 'djangofb', 'default_app')

    sys.stderr.write('Creating Facebook application %r...\n' % app_name)
    
    for d, subdirs, files in os.walk(template_dir):
        relative_dir = d[len(template_dir) + 1:]
        if relative_dir:
            os.mkdir(os.path.join(top_dir, relative_dir))
        subdirs[:] = [s for s in subdirs if not s.startswith('.')]
        for f in files:
            if f.endswith('.pyc'):
                continue
            path_old = os.path.join(d, f)
            path_new = os.path.join(top_dir, relative_dir, f)
            f_old = open(path_old, 'r')
            f_new = open(path_new, 'w')
            sys.stderr.write('Writing %s...\n' % path_new)
            f_new.write(f_old.read().replace('{{ project }}', project_name).replace('{{ app }}', app_name))
            f_new.close()
            f_old.close()

    sys.stderr.write('Done!\n\n')
    
    from django.conf import settings
    
    need_api_key = not hasattr(settings, 'FACEBOOK_API_KEY')
    need_middleware = not 'facebook.djangofb.FacebookMiddleware' in settings.MIDDLEWARE_CLASSES
    need_loader = not 'django.template.loaders.app_directories.load_template_source' in settings.TEMPLATE_LOADERS
    need_install_app = not '%s.%s' % (project_name, app_name) in settings.INSTALLED_APPS

    if need_api_key or need_middleware or need_loader or need_install_app:
        sys.stderr.write("""There are a couple of things you NEED to do before you can use this app:\n\n""")
        if need_api_key:
            sys.stderr.write(""" * Set FACEBOOK_API_KEY and FACEBOOK_SECRET_KEY to the appropriate values in settings.py\n\n""")
        if need_middleware:
            sys.stderr.write(""" * Add 'facebook.djangofb.FacebookMiddleware' to your MIDDLEWARE_CLASSES in settings.py\n\n""")
        if need_loader:
            sys.stderr.write(""" * Add 'django.template.loaders.app_directories.load_template_source' to your TEMPLATE_LOADERS in settings.py\n\n""")
        if need_install_app:
            sys.stderr.write(""" * Add '%s.%s' to your INSTALLED_APPS in settings.py\n\n""" % (project_name, app_name))

    sys.stderr.write("""The final step is to add (r'^%s/', include('%s.%s.urls')) to your urls.py, and then set your callback page in the application settings on Facebook to 'http://your.domain.com/%s/'.

Good luck!

""" % (project_name, project_name, app_name, project_name))
