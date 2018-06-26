import os
from flask import Flask, render_template, jsonify, request
import app
import pyping

gui_dir = os.path.join(os.getcwd(), "frontend/")  # development path
if not os.path.exists(gui_dir):  # frozen executable path
    gui_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend/build/")

server = Flask(__name__, static_folder=gui_dir, template_folder=gui_dir)
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
    host = request.values.get('host')
    r = pyping.ping(host)
    return jsonify(dict(
        delay=float(r.avg_rtt),
        destination_ip=r.destination_ip,
        ttl=r.ttl,
    ))


@server.route("/udp/ping", methods=['POST'])
def udp_ping():
    host = request.values.get('host')
    r = pyping.ping(host, udp=True)
    return jsonify(dict(
        delay=float(r.avg_rtt),
        destination_ip=r.destination_ip,
        ttl=r.ttl,
    ))


@server.route("/tcp/ping", methods=['POST'])
def tcp_ping():
    host = request.values.get('host')
    r = pyping.ping(host, udp=True)
    return jsonify(dict(
        delay=float(r.avg_rtt),
        destination_ip=r.destination_ip,
        ttl=r.ttl,
    ))


def run_server():
    server.run(host="127.0.0.1", port=23948, threaded=True)


if __name__ == "__main__":
    run_server()
