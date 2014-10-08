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
__version___ = '1.0.0'


log = logging.getLogger('authtokenslog')

USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:28.0) Gecko/20100101 Firefox/28.0"
PAGE_LOAD_TIMEOUT = 30


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


def phantomjs_setup(email, username, nickname, auth_thresh=.3):
    """Start PhantomJS and setup extensions and preferences. """

    # PhantomJS preferences.
    service_args = ['--ssl-protocol=any',
                    '--ignore-ssl-errors=true']

    # Change PhantomJS user agent to improve sites compatibility.
    desired_capabilities = {"phantomjs.page.settings.userAgent": USER_AGENT}

    ghost = crawler.GhostCrawler(email=email,
                                 username=username,
                                 nickname=nickname,
                                 service_args=service_args,
                                 desired_capabilities=desired_capabilities,
                                 auth_thresh=auth_thresh)

    ghost.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
    return ghost


def add_entry(cursor, website, cookies, tokens):
    """Add entry to a Sqlite3 database."""

    exist_website = cursor.execute("""
                    SELECT *
                    FROM website
                    WHERE domain == ?
                    """, (website[0],)).fetchone()

    # Integrity check: primary keys must be unique.
    if exist_website:
        log.info('Domain is not unique. I am going to overwrite it.')
        cursor.execute("DELETE FROM website WHERE domain == ?", (website[0],))

    log.info('Saving into database.\n')

    # Add website entry.
    cursor.execute("INSERT INTO website VALUES (?, ?, ?)", website)

    # Insert cookies into cookie table.
    for ck in cookies:
        cursor.execute("""
        INSERT INTO cookie
        VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)
        """, (ck['name'],
              ck['value'],
              ck['domain'],
              ck['path'],
              ck['secure'],
              ck['expiry'],
              website[0]))

    # Add authentication token.
    for token in tokens:

        cursor.execute("INSERT INTO token VALUES (NULL, ?)", (len(token),))

        # Retrieve token's auto-generated id.
        token_id = cursor.lastrowid

        # Retrieve cookies ids contained in an authentication token.
        placeholders = ', '.join('?' for _ in token)
        params = token + [website[0]]
        cookie_ids = cursor.execute("""
                     SELECT id
                     FROM cookie
                     WHERE name IN ({}) AND website == ?
                     """.format(placeholders), params)

        # Assign cookie to its respective token/s.
        for id_ in cookie_ids.fetchall():
            cursor.execute("INSERT INTO cookie_token VALUES (?, ?)",
                           (id_[0], token_id))


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
