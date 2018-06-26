from flask import url_for
from pprint import pprint


def test_icmp(client):
    r = client.post(url_for('icmp_ping'), json={'host': '103.94.185.59'})
    assert r.status_code == 200
    result = r.json['result']
    assert result['delay'] > 0
    assert result['destination_ip']
    assert result['ttl'] > 0
    print("\nICMP:")
    pprint(result)
    assert client.post(url_for('icmp_ping'), json={'host': '1212'}).status_code == 500


def test_udp(client):
    r = client.post(url_for('udp_ping'), json={'host': '103.94.185.59', 'port': 9999})
    assert r.status_code == 200
    result = r.json['result']
    assert result['delay'] > 0
    assert result['destination_ip']
    print("\nUDP:")
    pprint(result)
    assert client.post(url_for('icmp_ping'), json={'host': '111wq'}).status_code == 500


def test_tcp(client):
    r = client.post(url_for('tcp_ping'), json={'host': '103.94.185.59', 'port': 8888})
    assert r.status_code == 200
    result = r.json['result']
    assert result['delay'] > 0
    assert result['destination_ip']
    print('\n TCP:')
    pprint(result)
    assert client.post(url_for('tcp_ping'), json={'host': '111wq'}).status_code == 500


def test_host_locate(client):
    print('\n Locate:')
    r = client.post(url_for('host_locate'), json={'host': '103.94.185.59'})
    r = r.json
    print(r)
    assert r['address']
    assert r['x']
    assert r['y']
    assert client.post(url_for('host_locate'), json={'host': 'jkldsjkldsjlkds'}).status_code == 500
