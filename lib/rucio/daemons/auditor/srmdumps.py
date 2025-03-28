# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import glob
import hashlib
import logging
import operator
import os
import re
from configparser import RawConfigParser
from html.parser import HTMLParser
from typing import IO, TYPE_CHECKING, Any, Optional

import gfal2
import requests

from rucio.common.config import get_config_dirs
from rucio.common.constants import RseAttr
from rucio.common.dumper import DUMPS_CACHE_DIR, HTTPDownloadFailed, ddmendpoint_url, gfal_download_to_file, http_download_to_file, temp_file
from rucio.core.credential import get_signed_url
from rucio.core.rse import get_rse_id, list_rse_attributes

if TYPE_CHECKING:
    from collections.abc import Iterable

CHUNK_SIZE = 10485760

__DUMPERCONFIGDIRS = list(
    filter(
        os.path.exists,
        (
            os.path.join(confdir, 'auditor') for confdir in get_config_dirs()
        )
    )
)

OBJECTSTORE_NUM_TRIES = 30


class Parser(RawConfigParser):
    '''
    RawConfigParser subclass that doesn't modify the the name of the options
    and removes any quotes around the string values.
    '''
    remove_quotes_re = re.compile(r"^'(.+)'$")
    remove_double_quotes_re = re.compile(r'^"(.+)"$')

    def optionxform(
            self,
            optionstr: str
    ) -> str:
        return optionstr

    def get(
            self,
            section: str,
            option: str
    ) -> Any:
        value = super(Parser, self).get(section, option)
        if isinstance(value, str):
            value = self.remove_quotes_re.sub(r'\1', value)
            value = self.remove_double_quotes_re.sub(r'\1', value)
        return value

    def items(self, section):
        return [(name, self.get(section, name)) for name in self.options(section)]


def mkdir(dir_: str) -> None:
    '''
    This functions creates the `dir` directory if it doesn't exist. If `dir`
    already exists this function does nothing.
    '''
    try:
        os.mkdir(dir_)
    except OSError as error:
        if error.errno != 17:
            raise error


def get_newest(
        base_url: str,
        url_pattern: str,
        links: "Iterable[str]"
) -> tuple[str, datetime.datetime]:
    '''
    Returns a tuple with the newest url in the `links` list matching the
    pattern `url_pattern` and a datetime object representing the creation
    date of the url.

    The creation date is extracted from the url using datetime.strptime().
    '''
    logger = logging.getLogger('auditor.srmdumps')
    times = []

    pattern_components = url_pattern.split('/')

    date_pattern = '{0}/{1}'.format(base_url, pattern_components[0])
    if len(pattern_components) > 1:
        postfix = '/' + '/'.join(pattern_components[1:])
    else:
        postfix = ''

    for link in links:
        try:
            time = datetime.datetime.strptime(link, date_pattern)
        except ValueError:
            pass
        else:
            times.append((str(link) + postfix, time))

    if not times:
        msg = 'No links found matching the pattern {0} in {1}'.format(date_pattern, links)
        logger.error(msg)
        raise RuntimeError(msg)

    return max(times, key=operator.itemgetter(1))


def gfal_links(base_url: str) -> list[str]:
    '''
    Returns a list of the urls contained in `base_url`.
    '''
    ctxt = gfal2.creat_context()  # pylint: disable=no-member
    return ['/'.join((base_url, f)) for f in ctxt.listdir(str(base_url))]


class _LinkCollector(HTMLParser):
    def __init__(self):
        super(_LinkCollector, self).__init__()
        self.links = []

    def handle_starttag(
            self, tag: str,
            attrs: "Iterable[tuple[str, str]]"
    ) -> None:
        if tag == 'a':
            self.links.append(
                next(value for key, value in attrs if key == 'href')
            )


def http_links(base_url: str) -> list[str]:
    '''
    Returns a list of the urls contained in `base_url`.
    '''
    html = requests.get(base_url).text
    link_collector = _LinkCollector()

    link_collector.feed(html)
    links = []
    for link in link_collector.links:
        if not link.startswith('http://') and not link.startswith('https://'):
            links.append('{0}/{1}'.format(base_url, link))
        else:
            links.append(link)
    return links


protocol_funcs = {
    'davs': {
        'links': gfal_links,
        'download': gfal_download_to_file,
    },
    'gsiftp': {
        'links': gfal_links,
        'download': gfal_download_to_file,
    },
    'root': {
        'links': gfal_links,
        'download': gfal_download_to_file,
    },
    'srm': {
        'links': gfal_links,
        'download': gfal_download_to_file,
    },
    'http': {
        'links': http_links,
        'download': http_download_to_file,
    },
    'https': {
        'links': http_links,
        'download': http_download_to_file,
    },
}


def protocol(url: str) -> str:
    '''
    Given the URL `url` returns a string with the protocol part.
    '''
    proto = url.split('://')[0]
    if proto not in protocol_funcs:
        raise RuntimeError('Protocol {0} not supported'.format(proto))

    return proto


def get_links(base_url: str) -> list[str]:
    '''
    Given the URL `base_url` returns the URLs linked or contained in it.
    '''
    return protocol_funcs[protocol(base_url)]['links'](base_url)


def download(url: str, filename: IO) -> None:
    '''
    Given the URL `url` downloads its contents on `filename`.
    '''
    return protocol_funcs[protocol(url)]['download'](url, filename)


def parse_configuration(conf_dirs: Optional[list[str]] = None) -> Parser:
    '''
    Parses the configuration for the endpoints contained in `conf_dir`.
    Returns a ConfParser.RawConfParser subclass instance.
    '''
    conf_dirs = conf_dirs or __DUMPERCONFIGDIRS
    logger = logging.getLogger('auditor.srmdumps')
    if len(conf_dirs) == 0:
        logger.error('No configuration directory given to load SRM dumps paths')
        raise Exception('No configuration directory given to load SRM dumps paths')

    configuration = Parser({
        'disabled': False,
    })

    for conf_dir in conf_dirs:
        configuration.read(glob.glob(conf_dir + '/*.cfg'))
    return configuration


def download_rse_dump(
        rse: str,
        configuration: RawConfigParser,
        date: Optional[datetime.datetime] = None,
        destdir: str = DUMPS_CACHE_DIR
) -> tuple[str, datetime.datetime]:
    '''
    Downloads the dump for the given ddmendpoint. If this endpoint does not
    follow the standardized method to publish the dumps it should have an
    entry in the `configuration` object describing how to download the dump.

    `rse` is the DDMEndpoint name.

    `configuration` is a RawConfigParser subclass.

    `date` is a datetime instance with the date of the desired dump or None
    to download the latest available dump.

    `destdir` is the directory where the dump will be saved (the final component
    in the path is created if it doesn't exist).

    Return value: a tuple with the filename and a datetime instance with
    the date of the dump.
    '''
    logger = logging.getLogger('auditor.srmdumps')
    base_url, url_pattern = generate_url(rse, configuration)

    if not os.path.isdir(destdir):
        os.mkdir(destdir)

    # check for objectstores, which need to be handled differently
    rse_id = get_rse_id(rse)
    rse_attr = list_rse_attributes(rse_id)
    if RseAttr.IS_OBJECT_STORE in rse_attr and rse_attr[RseAttr.IS_OBJECT_STORE] is not False:
        tries = 1
        if date is None:
            # on objectstores, can't list dump files, so try the last N dates
            date = datetime.datetime.now()
            tries = OBJECTSTORE_NUM_TRIES
        path = ''
        while tries > 0:
            url = '{0}/{1}'.format(base_url, date.strftime(url_pattern))

            filename = '{0}_{1}_{2}_{3}'.format(
                'ddmendpoint',
                rse,
                date.strftime('%d-%m-%Y'),
                hashlib.sha1(url.encode()).hexdigest()
            )
            filename = re.sub(r'\W', '-', filename)
            path = os.path.join(destdir, filename)
            if not os.path.exists(path):
                logger.debug('Trying to download: "%s"', url)
                if RseAttr.SIGN_URL in rse_attr:
                    url = get_signed_url(rse_id, rse_attr[RseAttr.SIGN_URL], 'read', url)
                try:
                    with temp_file(destdir, final_name=filename) as (f, _):
                        download(url, f)
                    tries = 0
                except (HTTPDownloadFailed, gfal2.GError):
                    tries -= 1
                    date = date - datetime.timedelta(1)
    else:
        if date is None:
            logger.debug('Looking for site dumps in: "%s"', base_url)
            links = get_links(base_url)
            url, date = get_newest(base_url, url_pattern, links)
        else:
            url = '{0}/{1}'.format(base_url, date.strftime(url_pattern))

        filename = '{0}_{1}_{2}_{3}'.format(
            'ddmendpoint',
            rse,
            date.strftime('%d-%m-%Y'),
            hashlib.sha1(url.encode()).hexdigest()
        )
        filename = re.sub(r'\W', '-', filename)
        path = os.path.join(destdir, filename)

        if not os.path.exists(path):
            logger.debug('Trying to download: "%s"', url)
            with temp_file(destdir, final_name=filename) as (f, _):
                download(url, f)

    return (path, date)


def generate_url(
        rse: str,
        config: RawConfigParser
) -> tuple[str, str]:
    '''
    :param rse: Name of the endpoint.
    :param config: RawConfigParser instance which may have configuration
    related to the endpoint.
    :returns: Tuple with the URL where the links can be queried to find new
    dumps and the pattern used to parse the date of the dump of the files/directories
    listed..
    '''
    site = rse.split('_')[0]
    if site not in config.sections():
        base_url = ddmendpoint_url(rse) + 'dumps'
        url_pattern = 'dump_%Y%m%d'
    else:
        url_components = config.get(site, rse).split('/')
        # The pattern may not be the last component
        pattern_index = next(idx for idx, comp in enumerate(url_components) if '%m' in comp)
        base_url = '/'.join(url_components[:pattern_index])
        url_pattern = '/'.join(url_components[pattern_index:])

    return base_url, url_pattern
