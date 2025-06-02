import errno
import json
import logging
import os
import re
import subprocess
import urllib.parse as urlparse
from threading import Timer

from rucio.common import config, exception
from rucio.common.checksum import GLOBALLY_SUPPORTED_CHECKSUMS, PREFERRED_CHECKSUM
from rucio.common.constraints import STRING_TYPES
from rucio.rse.protocols import protocol

import opendal  # pylint: disable=import-error


TIMEOUT = config.config_get('deletion', 'timeout', False, None)

class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the srm protocol."""


    def __init__(self, protocol_attr, rse_settings, logger=logging.log):
        """ Initializes the object with information about the referred RSE.

            :param props: Properties derived from the RSE Repository
        """
        super(Default, self).__init__(protocol_attr, rse_settings, logger=logger)

        self.scheme = self.attributes['scheme']
        self.hostname = self.attributes['hostname']
        self.port = str(self.attributes['port'])
        self.logger = logger

    def path2pfn(self, path):
        """
            Returns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        self.logger(logging.DEBUG, 'xrootd.path2pfn: path: {}'.format(path))
        if not path.startswith('xroot') and not path.startswith('root'):
            if path.startswith('/'):
                return '%s://%s:%s/%s' % (self.scheme, self.hostname, self.port, path)
            else:
                return '%s://%s:%s//%s' % (self.scheme, self.hostname, self.port, path)
        else:
            return path



    def pfn2path(self, pfn):
        """
        Returns the path of a file given the pfn, i.e. scheme and hostname are subtracted from the pfn.

        :param path: pfn of a file

        :returns: path.
        """
        path = pfn.partition(self.attributes['prefix'])[2]
        return path

    def lfns2pfns(self, lfns):
        """
        Returns a fully qualified PFN for the file referred by path.

        :param path: The path to the file.

        :returns: Fully qualified PFN.
        """
        pfns = {}
        prefix = self.attributes['prefix']

        if not prefix.startswith('/'):
            prefix = ''.join(['/', prefix])
        if not prefix.endswith('/'):
            prefix = ''.join([prefix, '/'])

        lfns = [lfns] if isinstance(lfns, dict) else lfns
        for lfn in lfns:
            scope, name = lfn['scope'], lfn['name']
            if 'path' in lfn and lfn['path'] is not None:
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', self.attributes['hostname'], ':', str(self.attributes['port']), prefix, lfn['path']])
            else:
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', self.attributes['hostname'], ':', str(self.attributes['port']), prefix, self._get_path(scope=scope, name=name)])
        return pfns
    
    def _get_option_from_scheme(self, scheme :str):
        if scheme == "posix":
            scheme = "fs"
            root = self.attributes['prefix']

        if scheme == "davs":
            scheme = "webdav"
            endpoint = self.attributes['hostname'] + ":" + self.attributes['port']
            token = self.auth_token
            webdav_attributes = {
                    "scheme": scheme,
                    "options": {
                        "endpoint": endpoint,
                        "token":token,
                        "root": self.attributes['prefix']
                    }
                }
            return webdav_attributes

        if scheme == "https":
            scheme = "http"
            endpoint = self.attributes['hostname'] + ":" + self.attributes['port']
            token = self.auth_token


    
    def connect(self):
        try:
            webdav_attributes = self._get_option_from_scheme(self.attributes['prefix'])
            if webdav_attributes is None:
                raise exception.RSEAccessDenied("Could not determine connection options from scheme.")
            scheme = webdav_attributes.get('scheme')
            options = webdav_attributes.get('options', {})
            self.operator = opendal.Operator(scheme, **options)
        except Exception as e:
            raise exception.RSEAccessDenied(e)

    def stat(self, pfn):
        path = self.pfn2path(pfn=pfn)
        res = self.operator.stat(path)
        return res

    def rename(self, pfn, new_pfn):
        path = self.pfn2path(pfn=pfn)
        new_path = self.pfn2path(pfn=new_pfn)
        res = self.operator.rename(path)
        return res
    
    def get(self, pfn, dest='.', transfer_timeout=None):
        local_operator = opendal.Operator('fs', root = dest)

        remote_file_path = self.pfn2path(pfn=pfn)
        chunk_size: int = 4 * 1024 * 1024
        try:

            with self.operator.reader(remote_file_path) as remote_reader:
                # Get a writer for the local file
                with local_operator.writer(dest) as local_writer:
                    total_bytes_copied = 0
                    while True:
                        # Read a chunk from the remote
                        chunk = remote_reader.read(chunk_size)
                        if not chunk: # End of file
                            break
                        
                        # Write the chunk to the local file
                        local_writer.write(chunk)
                        total_bytes_copied += len(chunk)
        except Exception as e:
            print(f"\nAn unexpected error occurred during download of '{remote_file_path}': {e}")
            raise

    
    def put(self, pfn):
        path = self.pfn2path(pfn=pfn)
        res = self.operator.write(path)
        return res
