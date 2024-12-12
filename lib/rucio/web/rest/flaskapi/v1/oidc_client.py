from typing import TYPE_CHECKING

from flask import Flask, jsonify

from rucio.common.exception import AccessDenied, Duplicate
from rucio.common.utils import render_json
from rucio.gateway.oidc_client import add_oidc_client, list_oidc_client
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, generate_http_error_flask, json_parameters, param_get


class OIDCClient(ErrorHandlingMethodView):
    @check_accept_header_wrapper_flask(['application/json'])
    def post(self):
        parameters = json_parameters()
        try:
            add_oidc_client(
                allowed_scopes = param_get(parameters, 'allowed_scopes'),
                grant_types = param_get(parameters, 'grant_types'),
            )
        except Duplicate as error:
            return generate_http_error_flask(409, error)

        return 'Created', 201

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        oidc_clients = list_oidc_client()
        # Return the list of OIDC clients as a JSON response
        return jsonify(oidc_clients)

def blueprint():
    bp = AuthenticatedBlueprint('oidc_client', __name__)
    oidc_client_view = OIDCClient.as_view("oidc_client")
    bp.add_url_rule('/oidc_client', view_func = oidc_client_view, methods = ['post', 'get'])
    return bp

def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
