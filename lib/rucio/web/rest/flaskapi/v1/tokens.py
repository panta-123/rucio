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

from flask import Flask, jsonify, request

from rucio.common.exception import AccessDenied, RucioException
from rucio.common.utils import parse_response
from rucio.gateway.tokens import request_token
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, generate_http_error_flask, json_parameters, param_get, response_headers


class RequestToken(ErrorHandlingMethodView):
    """REST API endpoint to request an OIDC token."""

    def post(self):
        """
        ---
        summary: Request OIDC token
        description: Request an OIDC token for a specific RSE and operation.
        tags:
          - Token
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                  - rse
                  - operation
                properties:
                  rse:
                    type: string
                    description: "The RSE name."
                  operation:
                    type: string
                    enum: ["download", "upload"]
                    description: "The operation type."
        responses:
          200:
            description: "Token successfully generated"
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    token:
                      type: string
          400:
            description: "Cannot decode json parameter list."
          401:
            description: "Permission denied"
          503:
            description: "Failed to request token"
        """
        parameters = json_parameters(parse_response)
        rse = param_get(parameters, "rse")
        operation = param_get(parameters, "operation")
        vo = request.environ.get("vo", "def")
        try:
            token = request_token(rse=rse, operation=operation, vo=vo)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except RucioException as error:
            return generate_http_error_flask(503, error)

        return jsonify({"token": token}), 200


def blueprint(with_doc=False):
    bp = AuthenticatedBlueprint("token", __name__, url_prefix="/token")

    request_token_view = RequestToken.as_view("requesttoken")
    bp.add_url_rule("/request", view_func=request_token_view, methods=['post', ])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """Only used for sphinx documentation"""
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint(with_doc=True))
    return doc_app
