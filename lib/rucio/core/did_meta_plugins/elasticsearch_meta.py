# -*- coding: utf-8 -*-
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

import operator
from typing import TYPE_CHECKING

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError as ElasticConnectionError
from elasticsearch.helpers import BulkIndexError, bulk

from rucio.common import config
from rucio.common import exception
from rucio.common.types import InternalScope
from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin
from rucio.core.did_meta_plugins.filter_engine import FilterEngine

timeout = 100 # sec
IMMUTABLE_KEYS = [ 
    'scope',            # generated on insert
    'name',             # generated on insert
    'vo'                # generated on insert
]

class ElasticDidMeta(DidMetaPlugin):
    def __init__(self, host=None, port=None, user=None, password=None, index=None):
        super(ElasticDidMeta, self).__init__()
        if host is None:
            host = config.config_get('metadata', 'elastic_service_host')
        if port is None:
            port = config.config_get('metadata', 'elastic_service_port')
        if user is None:
            user = config.config_get('metadata', 'elastic_user')
        if password is None:
            password = config.config_get('metadata', 'elastic_password')
        if index is None:
            self.index = config.config_get('metadata', 'metaIndex')
        #if mapping is None:
        #    mapping = config_get('metadata', 'mapping')
        self.__url = "http://{user}:{password}@{host}:{port}"
        self.client = Elasticsearch(self.__url, timeout = timeout)

        self.plugin_name = "ELASTIC"


    def get_metadata(self, scope, name, *, session: "Optional[Session]" = None):
        """
        Get data identifier metadata.

        :param scope: The scope name
        :param name: The data identifier name
        :param session: The database session in use
        :returns: The metadata for the did
        """

        docID = "{}:{}".format(scope.internal, name)
        doc = self.client.get(self.index, docID)["_source"]
        if not doc:
            raise exception.DataIdentifierNotFound("No metadata found for did '{}:{}".format(scope, name))
        return doc

    def set_metadata(self, scope, name, key, value, recursive=False, *, session: "Optional[Session]" = None):
        """
        Set single metadata key.

        :param scope: the scope of did
        :param name: the name of the did
        :param key: the key to be added
        :param value: the value of the key to be added
        :param recursive: recurse into DIDs (not supported)
        :param session: The database session in use
        """
        self.set_metadata_bulk(scope=scope, name=name, meta={key: value}, recursive=recursive, session=session)

    def set_metadata_bulk(self, scope, name, meta, recursive=False, *, session: "Optional[Session]" = None):
        """
        Bulk set metadata keys.

        :param scope: the scope of did
        :param name: the name of the did
        :param meta: dictionary of metadata keypairs to be added
        :param recursive: recurse into DIDs (not supported)
        :param session: The database session in use
        """
        docID = "{}:{}".format(scope.internal, name)
        op_type = 'create'
        for key in IMMUTABLE_KEYS:
            if key in meta:
                meta.pop(key)
        meta['scope'] = scope.external
        meta['name'] = name
        meta['VO'] = scope.vo
        try:
            self.client.index(index=self.index, body=meta, id=docID, params={"op_type": op_type})
        except Exception as e:
            raise e

        
    def delete_metadata(self, scope, name, key, *, session: "Optional[Session]" = None):
        """
        Delete a key from metadata.

        :param scope: the scope of did
        :param name: the name of the did
        :param key: the key to be deleted
        """
        docID = "{}:{}".format(scope.internal, name)
        meta = {key: ""}
        try:
            self.client.update(index=self.index, id=docID,  body=meta)
        except Exception as e:
            raise e

    '''
    def list_dids(self, scope, filters, did_type='collection', ignore_case=False, limit=None,
                  offset=None, long=False, recursive=False, ignore_dids=None, *, session: "Optional[Session]" = None):
        if not ignore_dids:
            ignore_dids = set()

        # backwards compatability for filters as single {}.
        if isinstance(filters, dict):
            filters = [filters]

        # instantiate fe and create mongo query
        fe = FilterEngine(filters, model_class=None, strict_coerce=False)
        mongo_query_str = fe.create_mongo_query(
            additional_filters=[
                ('scope', operator.eq, scope.internal),
                ('vo', operator.eq, scope.vo)
            ]
        )
        # term query for exact match
        # "filter": [ 
        # { "term":  { key : value }},
        #{ "range": { "publish_date": { "gte": "2015-01-01" }}}
        # and is 
         q = Q("match", title='python') | Q("match", title='django')

        s = self._Search(self.index)
        for filter in fe:
                key : {}
        for key,value in condDict.items():
            kwargs = {key:value}
            s = s.filter('terms', **kwargs)
        for key,value in greater.items():
            kwargs = {key :{ 'gte':value}}
            s = s.filter('range', **kwargs)
        for key,value in smaller.items():
            kwargs = {key :{ 'lt':value}}
            s = s.filter('range', **kwargs)
        for key,value in smaller.items():
            kwargs = {key :{ 'lt':value}}
            s = s.filter('range', **kwargs)
    '''

    def manages_key(self, key, *, session: "Optional[Session]" = None):
        return True

    def get_plugin_name(self):
        """
        Returns a unique identifier for this plugin. This can be later used for filtering down results to this plugin only.

        :returns: The name of the plugin
        """
        return self.plugin_name