import base64

from flask import Flask, request, Response

from ocsp_resp import process_ocsp

app = Flask(__name__)


def _internal_ocsp(data: bytes):
    return Response(process_ocsp(data), mimetype='application/ocsp-response')


@app.route("/ocsp/<path:req>", methods=['GET'])
def route_ocsp_get(req):
    data = base64.b64decode(req)
    return _internal_ocsp(data)


@app.route("/ocsp", methods=['POST'])
@app.route("/ocsp/", methods=['POST'])
def route_ocsp_post():
    data = request.get_data()
    return _internal_ocsp(data)


@app.route("/health")
def route_health():
    return 'OK'


@app.route("/")
def route_main():
    return 'OCSP Server'


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8888)
