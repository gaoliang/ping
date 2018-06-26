import os
from flask import Flask, render_template, jsonify, request
import app
import pyping
import requests
from flask_cors import CORS

gui_dir = os.path.join(os.getcwd(), "frontend/")  # development path
if not os.path.exists(gui_dir):  # frozen executable path
    gui_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend/build/")

server = Flask(__name__, static_folder=gui_dir, template_folder=gui_dir)
CORS(server)
server.config["SEND_FILE_MAX_AGE_DEFAULT"] = 1  # disable caching


@server.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store'
    return response


@server.route("/")
def landing():
    """
    Render index.html. Initialization is performed asynchronously in initialize() function
    """
    return render_template("index.html")


@server.route("/init")
def initialize():
    """
    Perform heavy-lifting initialization asynchronously.
    :return:
    """
    can_start = app.initialize()

    if can_start:
        response = {
            "status": "ok",
        }
    else:
        response = {
            "status": "error"
        }

    return jsonify(response)


@server.route("/icmp/ping", methods=['POST'])
def icmp_ping():
    context = {**request.values, **request.json}
    p = pyping.Ping(destination=context['host'])
    r = p.ping_icmp()
    if not r:
        return jsonify(dict(
            success=False
        ))
    return jsonify(dict(
        success=True,
        result=r
    ))


@server.route("/udp/ping", methods=['POST'])
def udp_ping():
    context = {**request.values, **request.json}
    host = context.get('host')
    port = int(context.get('port'))
    p = pyping.Ping(host)
    r = p.ping_udp(port=port)
    if not r:
        return jsonify(dict(
            success=False
        ))
    return jsonify(dict(
        success=True,
        result=r
    ))


@server.route("/tcp/ping", methods=['POST'])
def tcp_ping():
    context = {**request.values, **request.json}
    host = context.get('host')
    port = int(context.get('port', 8888))
    p = pyping.Ping(host)
    r = p.ping_tcp(port=port)
    if not r:
        return jsonify(dict(
            success=False
        ))
    return jsonify(dict(
        success=True,
        result=r
    ))


@server.route("/host/locate", methods=['POST'])
def host_locate():
    context = {**request.values, **request.json}
    host = context.get('host')

    params = (
        ('access_key', '1d3588ce781b45f5ac3091e04c90b499'),
    )

    response = requests.get('http://api.ipstack.com/{}'.format(host), params=params)
    data = response.json()
    result = {
        'address': ', '.join([data['region_name'], data['city'], data['country_name']]),
        'x': float(data['latitude']),
        'y': float(data['longitude'])
    }
    return jsonify(result)


def run_server():
    server.run(host="0.0.0.0", port=23948, threaded=True)


if __name__ == "__main__":
    run_server()
