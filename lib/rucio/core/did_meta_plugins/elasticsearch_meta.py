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


'''
 Elasticsearch based metadata plugin.
'''

import datetime
import operator
from typing import TYPE_CHECKING, Any, Literal, Optional, Union

from elasticsearch import Elasticsearch
from elasticsearch import exceptions as elastic_exceptions

from rucio.common import config, exception
from rucio.core.did_meta_plugins.did_meta_plugin_interface import DidMetaPlugin
from rucio.core.did_meta_plugins.filter_engine import FilterEngine

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.orm import Session

    from rucio.common.types import InternalScope

IMMUTABLE_KEYS = [
    'scope',            # generated on insert
    'name',             # generated on insert
    'vo'                # generated on insert
]


class ElasticDidMeta(DidMetaPlugin):
    def __init__(
        self,
        hosts: Optional[list[str]] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        index: Optional[str] = None,
        archive_index: Optional[str] = None,
        use_ssl: Optional[bool] = False,
        verify_certs: bool = True,
        ca_certs: Optional[str] = None,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        request_timeout: int = 100,
        max_retries: int = 3,
        retry_on_timeout: bool = False,
        refresh: Optional[bool] = None
    ) -> None:
        super(ElasticDidMeta, self).__init__()
        hosts = hosts or [config.config_get('metadata', 'elastic_service_hosts')]
        user = user or config.config_get('metadata', 'elastic_user', False, None)
        password = password or config.config_get('metadata', 'elastic_password', False, None)
        self.index = index or config.config_get('metadata', 'meta_index', False, 'rucio_did_meta')
        self.archive_index = archive_index or config.config_get('metadata', 'archive_index', False, 'archive_meta')
        use_ssl = use_ssl or config.config_get_bool('metadata', 'use_ssl', False, False)
        ca_certs = ca_certs or config.config_get('metadata', 'ca_certs', False, None)
        client_cert = client_cert or config.config_get('metadata', 'client_cert', False, None)
        client_key = client_key or config.config_get('metadata', 'client_key', False, None)
        self.refresh = refresh or config.config_get_bool('metadata', 'elastic_refresh', False, False)

        self.es_config = {
            'hosts': hosts,
            'request_timeout': request_timeout,
            'max_retries': max_retries,
            'retry_on_timeout': retry_on_timeout
        }
        if user and password:
            self.es_config['basic_auth'] = (user, password)

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
        self._plugin_name = "ELASTIC"

    @staticmethod
    def _doc_id(scope: "InternalScope", name: str) -> str:
        """
        Build the canonical document id for a DID.

        Every read/write/delete path MUST use this helper so that the same
        DID always maps to the same Elasticsearch document id.
        """
        return f"{scope.internal}{name}"

    def drop_index(self) -> None:
        self.client.indices.delete(index=self.index)

    def get_metadata(
        self,
        scope: "InternalScope",
        name: str,
        *,
        session: "Optional[Session]" = None
    ) -> dict[str, Any]:
        """
        Get data identifier metadata.

        :param scope: The scope name
        :param name: The data identifier name
        :param session: The database session in use
        :returns: The metadata for the DID
        :raises DataIdentifierNotFound: If the DID metadata is not found.
        :raises RucioException: If another error occurs during the process.
        """
        doc_id = self._doc_id(scope, name)
        try:
            doc = self.client.get(index=self.index, id=doc_id)["_source"]
        except elastic_exceptions.NotFoundError as err:
            raise exception.DataIdentifierNotFound(f"No metadata found for DID '{scope}:{name}' not found") from err
        except Exception as err:
            raise exception.RucioException(err)
        return doc

    def set_metadata(
        self,
        scope: "InternalScope",
        name: str,
        key: str,
        value: str,
        recursive: bool = False,
        *,
        session: "Optional[Session]" = None
    ) -> None:
        """
        Set single metadata key.

        :param scope: the scope of DID
        :param name: the name of the DID
        :param key: the key to be added
        :param value: the value of the key to be added
        :param recursive: recurse into DIDs (not supported)
        :param session: The database session in use
        :raises DataIdentifierNotFound: If the DID is not found.
        :raises RucioException: If an error occurs while setting the metadata.
        """
        self.set_metadata_bulk(scope=scope, name=name, meta={key: value}, recursive=recursive, session=session)

    def set_metadata_bulk(
        self,
        scope: "InternalScope",
        name: str,
        meta: dict[str, Any],
        recursive: bool = False,
        *,
        session: "Optional[Session]" = None
    ) -> None:
        """
        Bulk set metadata keys.

        :param scope: the scope of DID
        :param name: the name of the DID
        :param meta: dictionary of metadata keypairs to be added
        :param recursive: recurse into DIDs (not supported)
        :param session: The database session in use
        :raises UnsupportedOperation: If recursive inserts are requested (currently unsupported).
        :raises RucioException: If an error occurs while setting the metadata.
        """
        if recursive:
            raise exception.UnsupportedOperation(
                f"'{self._plugin_name}' metadata module does not currently support recursive inserts of metadata"
            )

        doc_id = self._doc_id(scope, name)

        # Strip immutable keys from the caller-provided metadata.
        update_doc = {key: value for key, value in meta.items() if key not in IMMUTABLE_KEYS}

        upsert_doc = {
            'scope': str(scope.external),
            'name': name,
            'vo': scope.vo,
            **update_doc
        }
        try:
            self.client.update(index=self.index, id=doc_id,
                               doc=update_doc, upsert=upsert_doc,
                               refresh=self.refresh)
        except Exception as err:
            raise exception.RucioException(err)

    def delete_metadata(
        self,
        scope: "InternalScope",
        name: str,
        key: str,
        *,
        session: "Optional[Session]" = None
    ) -> None:
        """
        Delete a key from metadata.

        :param scope: the scope of DID
        :param name: the name of the DID
        :param key: the key to be deleted
        :raises DataIdentifierNotFound: If the DID is not found.
        :raises RucioException: If an error occurs while setting the metadata.
        """
        doc_id = self._doc_id(scope, name)
        try:
            doc = self.client.get(index=self.index, id=doc_id)

            if key in doc['_source']:
                script = {
                    "source": "ctx._source.remove(params['key'])",
                    "lang": "painless",
                    "params": {"key": key}
                }
                self.client.update(index=self.index, id=doc_id, script=script, refresh=self.refresh)
        except elastic_exceptions.NotFoundError as err:
            raise exception.DataIdentifierNotFound(f"No metadata found for DID '{scope}:{name}' not found") from err
        except Exception as err:
            raise exception.RucioException(err)

    def list_dids(
        self,
        scope: "InternalScope",
        filters: Union[list[dict[str, Any]], dict[str, Any]],
        did_type: Literal['all', 'collection', 'dataset', 'container', 'file'] = 'collection',
        ignore_case: bool = False,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        long: bool = False,
        recursive: bool = False,
        ignore_dids: Optional[list] = None,
        *,
        session: "Optional[Session]" = None
    ) -> "Iterator[dict[str, Any]]":
        """
        List DIDs (Data Identifier).

        :param scope: The scope of the DIDs to search.
        :param filters: The filters to apply to the DID search.
        :param did_type: The type of DID (default is 'collection').
        :param ignore_case: Whether to ignore case (default is False).
        :param limit: The maximum number of DIDs to return.
        :param offset: The number of leading results to skip (client-side pagination).
        :param long: Whether to return extended information (scope, name, did_type, bytes, length) (default is False).
        :param recursive: Whether to search recursively (currently unsupported).
        :param ignore_dids: A list of DIDs to ignore (default is an empty list).
        :param session: The database session in use.
        :returns: A generator yielding DIDs as strings (when `long` is False) or dictionaries (when `long` is True).
        :raises UnsupportedOperation: If recursive searches are requested (currently unsupported).
        :raises RucioException: If an error occurs during the search.
        """
        if recursive:
            raise exception.UnsupportedOperation(
                f"'{self._plugin_name}' metadata module does not currently support recursive searches"
            )

        seen_dids = set(ignore_dids) if ignore_dids else set()

        # backwards compatibility for filters as single {}.
        if isinstance(filters, dict):
            filters = [filters]

        # Create Elasticsearch query
        fe = FilterEngine(filters, model_class=None, strict_coerce=False)
        elastic_query_str = fe.create_elastic_query(
            additional_filters=[
                ('scope', operator.eq, str(scope.external)),
                ('vo', operator.eq, scope.vo)
            ]
        )
        pit = self.client.open_point_in_time(index=self.index, keep_alive="2m")
        pit_id = pit["id"]

        # Base query with point in time (pit) parameter.
        # A sort is required for search_after; sort on _shard_doc (the most
        # efficient tiebreaker for PIT pagination).
        query: dict[str, Any] = {
            "query": elastic_query_str,
            "sort": [{"_shard_doc": "asc"}],
            "source": ["scope", "name"] if not long else ["scope", "name", "did_type", "bytes", "length"],
            "pit": {"id": pit_id, "keep_alive": "2m"},
            "size": 10000
        }

        # 'from' cannot be combined with search_after/PIT pagination, so
        # offset is applied client-side by skipping leading hits.
        to_skip = offset or 0
        yielded = 0
        search_after = None
        try:
            while True:
                if search_after:
                    query["search_after"] = search_after
                results = self.client.search(**query)
                hits = results['hits']['hits']
                if not hits:
                    break

                for hit in hits:
                    if to_skip > 0:
                        to_skip -= 1
                        continue

                    did_full = f"{hit['_source']['scope']}:{hit['_source']['name']}"
                    if did_full in seen_dids:
                        continue
                    seen_dids.add(did_full)

                    if long:
                        yield {
                            'scope': hit['_source']['scope'],
                            'name': hit['_source']['name'],
                            'did_type': hit['_source'].get('did_type', 'N/A'),
                            'bytes': hit['_source'].get('bytes', 'N/A'),
                            'length': hit['_source'].get('length', 'N/A')
                        }
                    else:
                        yield hit['_source']['name']

                    yielded += 1
                    if limit and yielded >= limit:
                        return

                # Update search_after for the next iteration
                search_after = hits[-1]["sort"]
        finally:
            # Always delete the point in time when done
            self.client.close_point_in_time(id=pit_id)

    def on_delete(
        self,
        scope: "InternalScope",
        name: str,
        archive: bool = False,
        session: "Optional[Session]" = None
    ) -> None:
        """
        Delete a document and optionally archive it.

        :param scope: The scope of the document
        :param name: The name of the document
        :param archive: Whether to archive the document before deletion
        :raises DataIdentifierNotFound: If the DID is not found.
        :raises RucioException: If an error occurs while deleting the metadata.
        """
        doc_id = self._doc_id(scope, name)

        try:
            doc = self.client.get(index=self.index, id=doc_id)

            if archive:
                archived_doc = doc['_source']
                archived_doc['deleted_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                self.client.index(index=self.archive_index, id=doc_id, document=archived_doc, refresh=self.refresh)

            self.client.delete(index=self.index, id=doc_id, refresh=self.refresh)

        except elastic_exceptions.NotFoundError as err:
            raise exception.DataIdentifierNotFound(f"No metadata found for DID '{scope}:{name}' not found") from err
        except Exception as err:
            raise exception.RucioException(err)

    def get_metadata_archived(
        self,
        scope: "InternalScope",
        name: str,
        session: "Optional[Session]" = None
    ) -> dict[str, Any]:
        """
        Retrieve archived metadata for a given scope and name.

        :param scope: The scope of the document
        :param name: The name of the document
        :return: The archived metadata
        :raises DataIdentifierNotFound: If the DID is not found.
        :raises RucioException: If an error occurs while reading the metadata.
        """
        doc_id = self._doc_id(scope, name)

        try:
            return self.client.get(index=self.archive_index, id=doc_id)["_source"]
        except elastic_exceptions.NotFoundError as err:
            raise exception.DataIdentifierNotFound(f"No metadata found for DID '{scope}:{name}'") from err
        except Exception as err:
            raise exception.RucioException(err)

    def manages_key(
        self,
        key: str,
        *,
        session: "Optional[Session]" = None
    ) -> bool:
        return True
