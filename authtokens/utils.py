#!/usr/bin/env python
"""
Support library for 'detect_tokens.py'.
"""

# -*- coding: utf-8 -*-
import sys
import os
import time
import logging
import json
import datetime

from dateutil import parser

import crawler


__author__ = "Andrea Casini"
__license__ = "MIT"
__version___ = '1.0.0'


USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:28.0) Gecko/20100101 Firefox/28.0"
HARS_PATH = os.getcwd() + '/firefox/har/'

log = logging.getLogger('authtokens')


def firefox_setup(email,
                  username,
                  nickname,
                  password,
                  ignore_alerts=False,
                  auth_thresh=.3):
    """Start Firefox and setup extensions and preferences. """

    # Firefox preferences.
    firefox_prefs = [('intl.accept_languages', 'en'),        # set default language to english
                     ('general.useragent.locale', 'en-US')]  # set user current locale

    # Firefox extensions.
    extensions = ['firefox/extensions/firebug-2.0.2-fx.xpi',
                  'firefox/extensions/netExport-0.9b6.xpi']

    # Firebug preferences
    fb_ext = 'extensions.firebug.'

    firebug_prefs = [
        (fb_ext + 'currentVersion', '2.0.2'),   # Avoid Firebug start page
        (fb_ext + 'allPagesActivation', 'on'),  # Firebug activated for all pages
        (fb_ext + 'defaultPanelName', 'net'),   # The Net panel is selected by default
        (fb_ext + 'net.enableSites', True),     # Firebug Net panel is enabled
        (fb_ext + 'net.defaultPersist', True)]  # Preserve network traffic between page load.

    # NetExport preferences.
    netexport_prefs = [(fb_ext + 'netexport.alwaysEnableAutoExport', True), # Export HAR files.
                       (fb_ext + 'netexport.showPreview', False),           # Do not show a preview for exported data
                       (fb_ext + 'netexport.defaultLogDir', HARS_PATH)]     # Store HAR files here

    # Put it all together.
    preferences = firefox_prefs + firebug_prefs + netexport_prefs

    firefox = crawler.AuthenticationCrawler(email=email,
                                            username=username,
                                            nickname=nickname,
                                            password=password,
                                            extensions=extensions,
                                            preferences=preferences,
                                            ignore_alerts=ignore_alerts,
                                            auth_thresh=auth_thresh)

    firefox.set_page_load_timeout(30)
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

    ghost.set_page_load_timeout(30)
    return ghost


def get_http_cookies(domain):
    """Retrieve http cookies and http-only cookies names by analyzing the
    http responses recorded in the HAR files of the corresponding domain.

    Inputs
    ------
    domain : string
        the domain for which to detect http cookies.

    """
    http_cks = set()
    httponly_cks = set()
    har_filenames = [f for f in os.listdir(HARS_PATH) if domain in f]

    for filename in har_filenames:

        # Read HAR archive.
        with open(HARS_PATH + filename, 'rt') as f:
            har = json.load(f)

        # Iterate over the HTTP responses.
        for entry in har['log']['entries']:
            for har_ck in entry['response']['cookies']:
                is_expired = False

                # Check if cookie is expired.
                if 'expires' in har_ck.keys():
                    try:
                        expiry_date = parser.parse(har_ck['expires'])
                        today = datetime.datetime.now(expiry_date.tzinfo)
                        is_expired = today > expiry_date
                    except (TypeError, ValueError):
                        log.info('Unknown date format')

                # Accept only non-expired and non-deleted cookie.
                if har_ck['value'] != 'deleted' and not is_expired:
                    http_cks.add(har_ck['name'])

                # Check for http-only cookies.
                if 'httpOnly' in har_ck.keys():
                    if har_ck['httpOnly']:
                        httponly_cks.add(har_ck['name'])

    return http_cks, httponly_cks


def add_entry(cursor, website, cookies, tokens):
    """Add entry to a Sqlite3 database."""

    exist_website = cursor.execute("""
                    SELECT *
                    FROM website
                    WHERE domain == ?
                    """, (website[0],)).fetchone()

    # Integrity check: primary keys must be unique.
    if exist_website:
        log.info('Domain is not unique. Overwriting.')
        cursor.execute("DELETE FROM website WHERE domain == ?", (website[0],))

    log.info('Saving into database.\n')

    # Add website entry.
    cursor.execute("INSERT INTO website VALUES (?, ?, ?)", website)

    # Insert cookies into cookie table.
    for ck in cookies:
        cursor.execute("""
        INSERT INTO cookie
        VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ck['name'],
              ck['value'],
              ck['domain'],
              ck['path'],
              ck['secure'],
              ck['expiry'],
              ck['httponly'],
              ck['js'],
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
                     SELECT cookie_id
                     FROM cookie
                     WHERE name IN ({}) AND website == ?
                     """.format(placeholders), params)

        # Assign cookie to its respective token/s.
        for cookie_id in cookie_ids.fetchall():
            cursor.execute("INSERT INTO cookie_token VALUES (?, ?)",
                           (cookie_id[0], token_id))


def start_timer(n_seconds):
    """Start a timer and print remaining seconds in the output."""
    for sec in xrange(n_seconds):
        time.sleep(1)
        sys.stdout.write("\rYou have %d seconds to login!" % (n_seconds - sec - 1))
        sys.stdout.flush()
    sys.stdout.write("\n\n")


def delete_duplicates(cookies):
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


def clean_hars_directory(domain):
    """Delete HARS archive for the specified domain."""
    for filename in os.listdir(HARS_PATH):
        if domain in filename:
            os.remove(HARS_PATH + filename)