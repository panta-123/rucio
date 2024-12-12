""" ddd """

from flask import Blueprint, Flask, jsonify, request

from rucio.common.exception import UnsupportedRequestedContentType
from rucio.gateway.token_issuer import handle_token, jwks, openid_config_resource
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, generate_http_error_flask


class JWKS(ErrorHandlingMethodView):

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        try:
            res_jwks = jwks()
            logger.info(res_jwks)
        except Exception as error:
            return generate_http_error_flask(404, error)
        return jsonify(res_jwks)

class OPENID_WELLKNOWN(ErrorHandlingMethodView):
    """ dd"""

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        """ """
        try:
            res = openid_config_resource()
        except Exception as error:
            return generate_http_error_flask(404, error)
        return jsonify(res)
 
class HANDLE_TOKEN(ErrorHandlingMethodView):

    #@check_accept_header_wrapper_flask(['application/x-www-form-urlencoded'])
    def post(self):
        try:
            # Check for the correct content type
            content_type = request.headers.get('Content-Type', '')
            if 'application/x-www-form-urlencoded' not in content_type:
                logger.info(f"Invalid Content-Type: {content_type}")
                return generate_http_error_flask(415, "Unsupported Media Type: Expected application/x-www-form-urlencoded")
            data = request.form.to_dict()

            #if not auth:
            #    return generate_http_error_flask(401, "auth is required")

            #logger.info(auth)
            # Decode base64 encoded authorization credentials
            client_id = "1fd3bc08-3376-431f-b2a0-984c5a0ce677"
            client_secret = "e36246078c01fca52bc21ac32cc20ffacbae05086fc3107a56529133d7b5dc19"
            # Validate required fields
            if not client_id or not client_secret:
                return generate_http_error_flask(400, "Missing required fields: client_id or client_secret")
            # Call the gateway layer
            response = handle_token(
                data=data,
                client_id=client_id,
                client_secret=client_secret
            )
        except Exception as error:
            # Handle errors (e.g., validation, server errors)
            return generate_http_error_flask(500, str(error))
        # Return JSON response
        return jsonify(response)

def blueprint():
    public_bp = Blueprint('token_issuer', __name__)

    # Register JWKS view at /jwks
    jwks_view = JWKS.as_view('jwks')
    public_bp.add_url_rule('/jwks', view_func=jwks_view, methods=['GET'])

    # Register OPENID_WELLKNOWN view at /.well-known/openid-configuration
    wellknown_view = OPENID_WELLKNOWN.as_view('openid_wellknown')
    public_bp.add_url_rule('/.well-known/openid-configuration', view_func=wellknown_view, methods=['GET'])

    token_view = HANDLE_TOKEN.as_view('token_endpoint')
    public_bp.add_url_rule('/token', view_func=token_view, methods=['POST'])

    return public_bp
