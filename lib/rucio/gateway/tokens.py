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

from typing import Literal

from rucio.common.constants import RseAttr
from rucio.common.exception import RucioException
from rucio.core import oidc as oidc_core
from rucio.core import rse as rse_core
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session


def request_token(
    rse: str,
    operation: Literal["download", "upload"],
    vo: str = 'def',
) -> str:
    """
    Gateway for requesting an OIDC token.

    Raises RucioException if the token cannot be retrieved or is None.
    """
    if operation == "download":
        with db_session(DatabaseOperationType.READ) as session:
            filtered_prefixes = set()
            rse_id = rse_core.get_rse_id(rse=rse, vo=vo, session=session)
            audience = rse_core.determine_audience_for_rse(rse_id=rse_id)
            scopes = ["storage.read"]
            rse_protocols = rse_core.get_rse_protocols(rse_id, session=session)
            for protocol in rse_protocols["protocols"]:
                prefix = protocol["prefix"]
                if base_path := rse_core.get_rse_attribute(rse_id, RseAttr.OIDC_BASE_PATH):  # type: ignore (session parameter missing)
                    prefix = prefix.removeprefix(base_path)
                filtered_prefixes.add(prefix)
            all_scopes = [f"{s}:{p}" for s in scopes for p in filtered_prefixes]
            scope_request = " ".join(sorted(all_scopes))

    else:
        raise RucioException("upload operation is not permitted now.")

    try:
        token = oidc_core.request_token(audience=audience, scope=scope_request)
    except Exception as e:
        raise RucioException(f"Failed to request token: {e}")

    if token is None:
        raise RucioException(f"Failed to obtain token: received None for audience='{audience}', scope='{scope_request}'")

    return token
