#!/usr/bin/env python
"""
Support library for 'detect_tokens.py'
"""
import time
import sys
import logging

import crawler


__author__ = "Andrea Casini"
__license__ = "MIT"
__all__ = ["AuthenticationCrawler", "GhostCrawler"]
__version___ = '1.0.1'


log = logging.getLogger('authtokenslog')

PAGE_LOAD_TIMEOUT = 30
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:28.0) Gecko/20100101 Firefox/28.0"


def firefox_setup(email,
                  username,
                  nickname,
                  password,
                  ignore_alerts=False,
                  auth_thresh=.3):
    """Start Firefox and setup extensions and preferences. """

    # Firefox preferences.
    prefs = [('intl.accept_languages', 'en'),        # set default language to english
             ('general.useragent.locale', 'en-US')]  # set user current locale

    firefox = crawler.AuthenticationCrawler(email=email,
                                            username=username,
                                            nickname=nickname,
                                            password=password,
                                            preferences=prefs,
                                            ignore_alerts=ignore_alerts,
                                            auth_thresh=auth_thresh)

    firefox.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    return firefox


def phantomjs_setup(email, username, nickname, auth_thresh=.3, executable_path=None):
    """Start PhantomJS and setup extensions and preferences. """

    # PhantomJS preferences.
    service_args = ['--ssl-protocol=any',
                    '--ignore-ssl-errors=true']

    # Change PhantomJS user agent to improve sites compatibility.
    capabilities = {"phantomjs.page.settings.userAgent": USER_AGENT}

    ghost = crawler.GhostCrawler(email=email,
                                 username=username,
                                 nickname=nickname,
                                 service_args=service_args,
                                 capabilities=capabilities,
                                 executable_path=executable_path,
                                 auth_thresh=auth_thresh)

    ghost.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    return ghost


def start_timer(n_seconds):
    """Start a timer and print remaining seconds in the output."""
    for sec in xrange(n_seconds):
        time.sleep(1)
        sys.stdout.write("\rYou have %d seconds to login!" % (n_seconds - sec - 1))
        sys.stdout.flush()
    sys.stdout.write("\n\n")


def delete_duplicates_cookies(cookies):
    """Delete duplicate cookies i.e. cookies with the same name."""
    unique_cookies = []
    seen = set()
    for ck in cookies:
        if ck['name'] in seen:
            log.info('Deleting duplicate cookie: %s' % ck['name'])
        else:
            seen.add(ck['name'])
            unique_cookies.append(ck)
    return unique_cookies
