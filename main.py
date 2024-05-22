import uvicorn
from fastapi import FastAPI

from controllers.teas import TEA
from models.response import ResponseData, RequestData

app = FastAPI()


@app.get('/')
def index():
    return 'Hello, World!'


@app.post('/api/encrypt', response_model=ResponseData)
def encrypt(request_data: RequestData):
    try:
        key = request_data.key
        data = request_data.data
        encrypted_data = TEA.encrypt_tea(data, key)
        return ResponseData(status=200, message="Encoding successful", data=encrypted_data)

    except Exception as e:
        raise ResponseData(status=500, message="Encoding failed", data=str(e))


@app.post('/api/decrypt', response_model=ResponseData)
def decrypt(request_data: RequestData):
    try:
        key = request_data.key
        data = request_data.data
        decrypted_data = TEA.decrypt_tea(data, key)
        return ResponseData(status=200, message="Decoding successful", data=decrypted_data)

    except Exception as e:
        raise ResponseData(status=500, message="Decoding failed", data=str(e))


# if __name__ == '__main__':
#     #uvicorn.run(app)
#     uvicorn.run("app.main:app", reload=True)
