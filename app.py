from flask import Flask, request, jsonify
from pydantic import ValidationError
from controllers.teas import TEA
from models.response import ResponseData, RequestData

app = Flask(__name__)


@app.route('/')
def index():
    return 'Hello, World!'


@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    try:
        request_data = RequestData(**request.json)
        key = request_data.key
        data = request_data.data
        encrypted_data = TEA.encrypt_tea(data, key)
        response_data = ResponseData(status=200, message="Encoding successful", data=encrypted_data)

    except ValidationError as e:
        response_data = ResponseData(status=400, message="Invalid input data", data=str(e))
    except Exception as e:
        response_data = ResponseData(status=500, message=str(e), data="")

    return jsonify(response_data.dict())


@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    try:
        request_data = RequestData(**request.json)
        key = request_data.key
        data = request_data.data
        decrypted_data = TEA.decrypt_tea(data, key)
        response_data = ResponseData(status=200, message="Decoding successful", data=decrypted_data)

    except ValidationError as e:
        response_data = ResponseData(status=400, message="Invalid input data", data=str(e))
    except Exception as e:
        response_data = ResponseData(status=500, message=str(e), data="")

    return jsonify(response_data.dict())


if __name__ == '__main__':
    app.run(debug=True)
    #app.run(host='0.0.0.0', port=5000, debug=True)
