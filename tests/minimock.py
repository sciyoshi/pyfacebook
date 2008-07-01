# (c) 2006 Ian Bicking, Mike Beachy, and contributors
# Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php
r"""
minimock is a simple library for doing Mock objects with doctest.
When using doctest, mock objects can be very simple.

Here's an example of something we might test, a simple email sender::

    >>> import smtplib
    >>> def send_email(from_addr, to_addr, subject, body):
    ...     conn = smtplib.SMTP('localhost')
    ...     msg = 'To: %s\nFrom: %s\nSubject: %s\n\n%s' % (
    ...         to_addr, from_addr, subject, body)
    ...     conn.sendmail(from_addr, [to_addr], msg)
    ...     conn.quit()

Now we want to make a mock ``smtplib.SMTP`` object.  We'll have to
inject our mock into the ``smtplib`` module::

    >>> smtplib.SMTP = Mock('smtplib.SMTP')
    >>> smtplib.SMTP.mock_returns = Mock('smtp_connection')

Now we do the test::

    >>> send_email('ianb@colorstudy.com', 'joe@example.com',
    ...            'Hi there!', 'How is it going?')
    Called smtplib.SMTP('localhost')
    Called smtp_connection.sendmail(
        'ianb@colorstudy.com',
        ['joe@example.com'],
        'To: joe@example.com\nFrom: ianb@colorstudy.com\nSubject: Hi there!\n\nHow is it going?')
    Called smtp_connection.quit()

Voila!  We've tested implicitly that no unexpected methods were called
on the object.  We've also tested the arguments that the mock object
got.  We've provided fake return calls (for the ``smtplib.SMTP()``
constructor).  These are all the core parts of a mock library.  The
implementation is simple because most of the work is done by doctest.
"""

import warnings
warnings.warn(
    "The module from http://svn.colorstudy.com/home/ianb/recipes/minimock.py is deprecated; "
    "please install the MiniMock package",
    DeprecationWarning, stacklevel=2)

__all__ = ["mock", "restore", "Mock"]

import inspect

# A list of mocked objects. Each item is a tuple of (original object,
# namespace dict, object name, and a list of object attributes).
#
mocked = []

def lookup_by_name(name, nsdicts):
    """
    Look up an object by name from a sequence of namespace dictionaries.
    Returns a tuple of (nsdict, object, attributes); nsdict is the
    dictionary the name was found in, object is the base object the name is
    bound to, and the attributes list is the chain of attributes of the
    object that complete the name.

        >>> import os
        >>> nsdict, name, attributes = lookup_by_name("os.path.isdir", 
        ...     (locals(),))
        >>> name, attributes
        ('os', ['path', 'isdir'])
        >>> nsdict, name, attributes = lookup_by_name("os.monkey", (locals(),))
        Traceback (most recent call last):
          ...
        NameError: name 'os.monkey' is not defined
            
    """
    for nsdict in nsdicts:
        attrs = name.split(".")
        names = []

        while attrs:
            names.append(attrs.pop(0))
            obj_name = ".".join(names)

            if obj_name in nsdict:
                attr_copy = attrs[:]
                tmp = nsdict[obj_name]
                try:
                    while attr_copy:
                        tmp = getattr(tmp, attr_copy.pop(0))
                except AttributeError:
                    pass
                else:
                    return nsdict, obj_name, attrs

    raise NameError("name '%s' is not defined" % name)

def mock(name, nsdicts=None, mock_obj=None, **kw):
    """
    Mock the named object, placing a Mock instance in the correct namespace
    dictionary. If no iterable of namespace dicts is provided, use
    introspection to get the locals and globals of the caller of this
    function.

    All additional keyword args are passed on to the Mock object
    initializer.

    An example of how os.path.isfile is replaced:

        >>> import os
        >>> os.path.isfile
        <function isfile at ...>
        >>> isfile_id = id(os.path.isfile)
        >>> mock("os.path.isfile", returns=True)
        >>> os.path.isfile
        <Mock ... os.path.isfile>
        >>> os.path.isfile("/foo/bar/baz")
        Called os.path.isfile('/foo/bar/baz')
        True
        >>> mock_id = id(os.path.isfile)
        >>> mock_id != isfile_id
        True

    A second mock object will replace the first, but the original object
    will be the one replaced with the replace() function.

        >>> mock("os.path.isfile", returns=False)
        >>> mock_id != id(os.path.isfile)
        True
        >>> restore()
        >>> os.path.isfile
        <function isfile at ...>
        >>> isfile_id == id(os.path.isfile)
        True

    """
    if nsdicts is None:
        stack = inspect.stack()
        try:
            # stack[1][0] is the frame object of the caller to this function
            globals_ = stack[1][0].f_globals
            locals_ = stack[1][0].f_locals
            nsdicts = (locals_, globals_)
        finally:
            del(stack)

    if mock_obj is None:
        mock_obj = Mock(name, **kw)

    nsdict, obj_name, attrs = lookup_by_name(name, nsdicts)

    # Get the original object and replace it with the mock object.
    tmp = nsdict[obj_name]
    if not attrs:
        original = tmp
        nsdict[obj_name] = mock_obj
    else:
        for attr in attrs[:-1]:
            tmp = getattr(tmp, attr)
        original = getattr(tmp, attrs[-1])
        setattr(tmp, attrs[-1], mock_obj)

    mocked.append((original, nsdict, obj_name, attrs))

def restore():
    """
    Restore all mocked objects.

    """
    global mocked

    # Restore the objects in the reverse order of their mocking to assure
    # the original state is retrieved.
    while mocked:
        original, nsdict, name, attrs = mocked.pop()
        if not attrs:
            nsdict[name] = original
        else:
            tmp = nsdict[name]
            for attr in attrs[:-1]:
                tmp = getattr(tmp, attr)
            setattr(tmp, attrs[-1], original)
    return

class Mock(object):

    def __init__(self, name, returns=None, returns_iter=None,
                returns_func=None, raises=None):
        self.mock_name = name
        self.mock_returns = returns
        if returns_iter is not None:
            returns_iter = iter(returns_iter)
        self.mock_returns_iter = returns_iter
        self.mock_returns_func = returns_func
        self.mock_raises = raises
        self.mock_attrs = {}

    def __repr__(self):
        return '<Mock %s %s>' % (hex(id(self)), self.mock_name)

    def __call__(self, *args, **kw):
        parts = [repr(a) for a in args]
        parts.extend(
            '%s=%r' % (items) for items in sorted(kw.items()))
        msg = 'Called %s(%s)' % (self.mock_name, ', '.join(parts))
        if len(msg) > 80:
            msg = 'Called %s(\n    %s)' % (
                self.mock_name, ',\n    '.join(parts))
        print msg
        return self._mock_return(*args, **kw)

    def _mock_return(self, *args, **kw):
        if self.mock_raises is not None:
            raise self.mock_raises
        elif self.mock_returns is not None:
            return self.mock_returns
        elif self.mock_returns_iter is not None:
            try:
                return self.mock_returns_iter.next()
            except StopIteration:
                raise Exception("No more mock return values are present.")
        elif self.mock_returns_func is not None:
            return self.mock_returns_func(*args, **kw)
        else:
            return None

    def __getattr__(self, attr):
        if attr not in self.mock_attrs:
            if self.mock_name:
                new_name = self.mock_name + '.' + attr
            else:
                new_name = attr
            self.mock_attrs[attr] = Mock(new_name)
        return self.mock_attrs[attr]

__test__ = {
    "mock" :
    r"""
    An additional test for mocking a function accessed directly (i.e.
    not via object attributes).

    >>> import os
    >>> rename = os.rename
    >>> orig_id = id(rename)
    >>> mock("rename")
    >>> mock_id = id(rename)
    >>> mock("rename")
    >>> mock_id != id(rename)
    True
    >>> restore()
    >>> orig_id == id(rename) == id(os.rename)
    True

    The example from the module docstring, done with the mock/restore
    functions.

    >>> import smtplib
    >>> def send_email(from_addr, to_addr, subject, body):
    ...     conn = smtplib.SMTP('localhost')
    ...     msg = 'To: %s\nFrom: %s\nSubject: %s\n\n%s' % (
    ...         to_addr, from_addr, subject, body)
    ...     conn.sendmail(from_addr, [to_addr], msg)
    ...     conn.quit()

    >>> mock("smtplib.SMTP", returns=Mock('smtp_connection'))
    >>> send_email('ianb@colorstudy.com', 'joe@example.com',
    ...            'Hi there!', 'How is it going?')
    Called smtplib.SMTP('localhost')
    Called smtp_connection.sendmail(
        'ianb@colorstudy.com',
        ['joe@example.com'],
        'To: joe@example.com\nFrom: ianb@colorstudy.com\nSubject: Hi there!\n\nHow is it going?')
    Called smtp_connection.quit()
    >>> restore()

    """,
}

if __name__ == '__main__':
    import doctest
    doctest.testmod(optionflags=doctest.ELLIPSIS)
