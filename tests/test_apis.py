from flask import url_for


def test_icmp(client):
    r = client.post(url_for('icmp_ping'), data={'host': 'www.bing.com'})
    assert r.status_code == 200
    assert r.json['delay'] > 0
    assert r.json['destination_ip']
    assert r.json['ttl'] > 0
    print(r.json)


def test_udp(client):
    r = client.post(url_for('udp_ping'), data={'host': '127.0.0.1'})
    assert r.status_code == 200
    print(r.json)
