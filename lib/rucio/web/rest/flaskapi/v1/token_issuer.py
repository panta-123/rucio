from flask import Blueprint, Flask, jsonify, request

from rucio.common.exception import UnsupportedRequestedContentType
from rucio.gateway.token_issuer import jwks, openid_config_resource
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, generate_http_error_flask


class JWKS(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        try:
            res_jwks = jwks()
        except Exception as error:
            return generate_http_error_flask(404, error)
        return jsonify(res_jwks)

class OPENID_WELLKNOWN(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        try:
            res = openid_config_resource()
        except Exception as error:
            return generate_http_error_flask(404, error)
        return jsonify(res)

def create_public_blueprint():
    public_bp = Blueprint('public', __name__)

    # Register JWKS view at /jwks
    jwks_view = JWKS.as_view('jwks')
    public_bp.add_url_rule('/jwks', view_func=jwks_view, methods=['GET'])

    # Register OPENID_WELLKNOWN view at /.well-known/openid-configuration
    wellknown_view = OPENID_WELLKNOWN.as_view('openid_wellknown')
    public_bp.add_url_rule('/.well-known/openid-configuration', view_func=wellknown_view, methods=['GET'])

    return public_bp
