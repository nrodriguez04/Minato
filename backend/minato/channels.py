from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity

channels_blueprint = Blueprint('channels', __name__)

@channels_blueprint.route('/create', methods=['POST'])
@jwt_required()
def create_channel():
    # ...

@channels_blueprint.route('/update', methods=['PUT'])
@jwt_required()
def update_channel():
    # ...

@channels_blueprint.route('/delete', methods=['DELETE'])
@jwt_required()
def delete_channel():
    # ...
