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

#
# Author(s):
# - Anil Panta <anilpanta2@gmail.con>, 2023

'''
 Elasticsearch based metadata plugin.
'''
import operator
from typing import TYPE_CHECKING
import datetime

from elasticsearch import Elasticsearch
from elasticsearch.helpers import BulkIndexError, bulk
from elasticsearch.exceptions import (
        ConnectionError as ElasticConnectionError,
        TransportError,
        NotFoundError,
        RequestError,
    )

from rucio.common import config
from rucio.common import exception
from rucio.common.types import InternalScope
from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin
from rucio.core.did_meta_plugins.filter_engine import FilterEngine

if TYPE_CHECKING:
    from sqlalchemy.orm import Session
    from typing import Optional, Dict, Any
    from rucio.common.types import InternalScope


timeout = 100  # sec
IMMUTABLE_KEYS = [
    'scope',            # generated on insert
    'name',             # generated on insert
    'vo'                # generated on insert
]

class ElasticDidMeta(DidMetaPlugin):
    def __init__(
        self,
        hosts: Optional[list[str]] = None,
        port: Optional[int] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        index: Optional[str] = None,
        archive_index: Optional[str] = None,
        use_ssl: Optional[bool] = False,
        verify_certs: bool = True,
        ca_certs: Optional[str] = None,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        request_timeout: int = 30,
        max_retries: int = 3,
        retry_on_timeout: bool = False
    ):
        super(ElasticDidMeta, self).__init__()
        self.hosts = hosts or [config.config_get('metadata', 'elastic_service_host')]
        self.port = port or config.config_get('metadata', 'elastic_service_port', False, 9200)
        self.user = user or config.config_get('metadata', 'elastic_user', False, '')
        self.password = password or config.config_get('metadata', 'elastic_password', False, '')
        self.index = index or config.config_get('metadata', 'meta_index', False, 'rucio_did_meta')
        self.archive_index = archive_index or config.config_get('metadata', 'archive_index', False, 'archive_meta')

        self.es_config: Dict[str, Any] = {
            'hosts': self.hosts,
            'port': self.port,
            'timeout': request_timeout,
            'max_retries': max_retries,
            'retry_on_timeout': retry_on_timeout
        }
        if self.user and self.password:
            self.es_config['basic_auth'] = (self.user, self.password)

        if use_ssl:
            self.es_config.update({
                'ca_certs': ca_certs,
                'verify_certs': verify_certs,
                })
            if client_cert and client_key:
                self.es_config.update({
                'client_cert': client_cert,
                'client_key': client_key
                })

        self.client = Elasticsearch(**self.es_config)
        self.plugin_name = "ELASTIC"

    def drop_index(self):
        self.client.indices.delete(index=self.index, ignore=[400, 404])

    def get_metadata(self, scope, name, *, session: "Optional[Session]" = None):
        """
        Get data identifier metadata.

        :param scope: The scope name
        :param name: The data identifier name
        :param session: The database session in use
        :returns: The metadata for the did
        """

        doc_id = f"{scope.internal}{name}"
        try:
            doc = self.client.get(index=self.index, id=doc_id)["_source"]
        except NotFoundError as not_found_error:
            raise exception.DataIdentifierNotFound(
                f"No metadata found for DID '{scope}:{name}'"
            ) from not_found_error
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
        doc_id = f"{scope.internal}{name}"
        for key in IMMUTABLE_KEYS:
            if key in meta:
                meta.pop(key)
        try:
            doc = self.get_metadata(scope, name)
            doc.update(meta)
            print(meta)
            try:
                self.client.index(index=self.index, document=doc, id=doc_id, refresh="true")
            except Exception as e:
                raise e
        except NotFoundError:
            meta['scope'] = str(scope.external)
            meta['name'] = str(name)
            meta['vo'] = str(scope.vo)
            _doc = {}
            _doc.update(meta)
            self.client.index(index=self.index, document=meta, id=doc_id)

    
    def delete_metadata(self, scope, name, key, *, session: "Optional[Session]" = None):
        """
        Delete a key from metadata.

        :param scope: the scope of did
        :param name: the name of the did
        :param key: the key to be deleted
        """
        doc_id = f"{scope.internal}{name}"
        try:
            # First, get the current document
            doc = self.client.get(index=self.index, id=doc_id)
  
            # Check if the key exists in the document
            if key in doc['_source']:
                # Use script to remove the field
                script = {
                    "script": {
                        "source": f"ctx._source.remove('{key}')",
                        "lang": "painless"
                    }
                }
                self.client.update(index=self.index, id=doc_id, body=script)
        except Exception as err:
            raise exception.DataIdentifierNotFound(err)


    def list_dids(self, scope, filters, did_type='collection', ignore_case=False, limit=None,
                  offset=None, long=False, recursive=False, ignore_dids=None, *, session: "Optional[Session]" = None):
        if not ignore_dids:
            ignore_dids = set()

        # backwards compatability for filters as single {}.
        if isinstance(filters, dict):
            filters = [filters]

        # Create Elasticsearch query
        fe = FilterEngine(filters, model_class=None, strict_coerce=False)
        elastic_query_str = fe.create_elastic_query(
            additional_filters=[
                ('scope', operator.eq, str(scope.external)),
                ('vo', operator.eq, str(scope.vo))
            ]
        )
        pit = self.client.open_point_in_time(index=self.index, keep_alive="2m")
        pit_id = pit["id"]
        # Base query with point in time(pit) paramter.
        # sort is needed for search_after, so we use scope sort (random choice)
        query = {
            "query": elastic_query_str,
            "sort": [{"scope": "asc"}],
            "_source": ["scope", "name"] if not long else ["scope", "name", "did_type", "bytes", "length"],
            "pit": {"id": pit_id, "keep_alive": "2m"}
        }

        # Add sorting and pagination
        if offset:
            query["from"] = offset
        size = limit if limit else 10000
        query["size"] = size
        search_after = None
        total_processed = 0
        try:
            while True:
                if search_after:
                    query["search_after"] = search_after
                    query.pop("from", None)

                # Execute search
                results = self.client.search(body=query)
                hits = results['hits']['hits']
                if not hits:
                    break

                for hit in hits:
                    did_full = f"{hit['_source']['scope']}:{hit['_source']['name']}"
                    if did_full not in ignore_dids:
                        ignore_dids.add(did_full)
                        if long:
                            yield {
                                'scope': (hit['_source']['scope']),
                                'name': hit['_source']['name'],
                                'did_type': hit['_source'].get('did_type', 'N/A'),
                                'bytes': hit['_source'].get('bytes', 'N/A'),
                                'length': hit['_source'].get('length', 'N/A')
                            }
                        else:
                            yield hit['_source']['name']

                    total_processed += 1
                    if limit and total_processed >= limit:
                        break

                # Update search_after for the next iteration
                search_after = hits[-1]["sort"]

        finally:
            # Always delete the point in time when done
            self.client.close_point_in_time(body={"id": pit_id})

        if recursive:
            raise exception.UnsupportedOperation(f"'{self.plugin_name.lower()}' metadata module does not currently support recursive searches")

    def on_delete(self, scope: "InternalScope", name: str, archive: bool = False, session: "Optional[Session]" = None) -> None:
        """
        Delete a document and optionally archive it.
        
        :param scope: The scope of the document
        :param name: The name of the document
        :param archive: Whether to archive the document before deletion
        """
        doc_id = f"{scope}{name}"

        try:
            # Get the current document
            doc = self.client.get(index=self.index, id=doc_id)

            if archive:
                # Archive the document
                archived_doc = doc['_source']
                archived_doc['deleted_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                self.client.index(index=self.archive_index, id=doc_id, body=archived_doc)
                print(f"Archived document: {doc_id}")

            # Delete the document from the main index
            self.client.delete(index=self.index, id=doc_id)
            print(f"Deleted document: {doc_id}")

        except NotFoundError  as err:
            raise exception.DataIdentifierNotFound(err)
        except Exception as e:
            raise e

    def get_metadata_archived(self, scope: "InternalScope", name: str, session: "Optional[Session]" = None) -> None:
        """
        Retrieve archived metadata for a given scope and name.
        
        :param scope: The scope of the document
        :param name: The name of the document
        :return: The archived metadata or None if not found
        """
        doc_id = f"{scope}{name}"

        try:
            doc = self.client.get(index=self.archive_index, id=doc_id)["_source"]
            return doc
        except NotFoundError:
            raise exception.DataIdentifierNotFound("No metadata found for did '{}:{}".format(scope, name))

    def manages_key(self, key, *, session: "Optional[Session]" = None) -> bool:
        return True

    def get_plugin_name(self) -> str:
        """
        Returns a unique identifier for this plugin. This can be later used for filtering down results to this plugin only.

        :returns: The name of the plugin
        """
        return self.plugin_name
