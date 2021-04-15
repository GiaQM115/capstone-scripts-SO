import requests, json, ipaddress, datetime, traceback, socket, time, re

types = ["syslog", "firewall", "ids", "osquery"] # , "ossec"]

time_query = '{"query" : {"range": {"@timestamp": {"gte": "now-2m/m","lte": "now/m"}}}}'

HOST = socket.gethostname()

def sendData(s, data):
	s.send(data.encode())

def formatDate(dt):
	date = dt[0:dt.index('T')]
	time = dt[dt.index('T')+1:dt.index('.')]
	return date + " " + time

def parseSyslog(hit):
	data = {}
	diffFound = False
	data['type'] = "SYSLOG"
	global ipv4
	host = hit['_source']['log']['source']['address']
	msg = hit['_source']['message'].split(',')
	# find IPs/addresses
	ips = []
	date = []
	for element in msg:
		try:
			ipaddress.ip_address(element)
			ips.append(element)
		except:
			# not a valid IP
			try:
				datetime.datetime.strptime(element, '%Y/%m/%d %H:%M:%S')
				date.append(element)
			except:
				pass
	for ip in ips:
		diffFound = False
		a = ipaddress.ip_network(ip, strict=False).network_address
		if diffFound:
			break
		for b in ips:
			if ipaddress.ip_network(b, strict=False).network_address != a:
				diffFound = True
				break
	if diffFound:
		data['host'] = host
		data['ips'] = list(dict.fromkeys(ips))
		data['eventTime'] = list(dict.fromkeys(date))
		data['date'] = formatDate(hit['_source']['ingest']['timestamp'])
	else:
		data = None
	return data


def parseFirewall(hit):
	data = {}
	data['type'] = 'FIREWALL'
	data['ipport'] = hit['_source']['log']['source']['address']
	data['dip'] = hit['_source']['destination']['ip']
	data['sip'] = hit['_source']['source']['ip']
	a = ipaddress.ip_network(data['dip']).network_address
	b = ipaddress.ip_network(data['sip']).network_address
	if a == b:
		return None
	try:
		data['dport'] = hit['_source']['destination']['geo']['port']
	except:
		try:
			data['dport'] = hit['_source']['destination']['port']
		except:
			pass
	try:
		data['dloc'] = hit['_source']['destination']['geo']['region-iso-code']
	except:
		pass
	try:
		data['sport'] = hit['_source']['source']['port']
	except:
		pass
	try:
		data['app'] = hit['_source']['source']['application']
	except:
		pass
	data['date'] = formatDate(hit['_source']['ingest']['timestamp'])
	return data

def parseIDS(hit):
	data = {}
	data['type'] = 'IDS'
	data['host'] = hit['_source']['host']['name']
	data['dip'] = hit['_source']['destination']['ip']
	data['sip'] = hit['_source']['source']['ip']
	a = ipaddress.ip_network(data['dip']).network_address
	b = ipaddress.ip_network(data['sip']).network_address
	if a == b:
		return None
	data['date'] = formatDate(hit['_source']['ingest']['timestamp'])
	return data


def parseOSquery(hit):
	data = {}
	diffFound = False
	data['type'] = 'OSQUERY'
	data['host'] = hit['_source']['osquery']['result']['hostname']
	ips = []
	try:
		ips.append(hit['_source']['osquery']['result']['endpoint_ip1'])
	except:
		pass
	try:
		ips.append(hit['_source']['osquery']['result']['endpoint_ip2'])
	except:
		pass
	if len(ips) > 0:
		data['ips'] = list(dict.fromkeys(ips))
	for ip in ips:
		diffFound = False
		a = ipaddress.ip_network(ip, strict=False).network_address
		if diffFound:
			break
		for b in ips:
			if ipaddress.ip_network(b, strict=False).network_address != a:
				diffFound = True
				break
	if not diffFound:
		return None
	data['event'] = hit['_source']['osquery']['result']['name']
	date = int(hit['_source']['osquery']['result']['unixTime'])
	date = datetime.datetime.utcfromtimestamp(date).strftime('%Y-%m-%d %H:%M:%S')
	data['date'] = date
	msg = hit['_source']['message']
	if re.search(r'fail', msg.lower(), re.I):
		data['error'] = msg
	return data

def parseOSSEC(hit):
	global HOST
	data = {}
	data['type'] = 'OSSEC'
	data['host'] = hit['_source']['agent']['name']
	if data['host'] == HOST:
		return None
	try:
		try:
			data['host'] = hit['_source']['winlog']['computer']
		except:
			pass
		data['event'] = hit['_source']['winlog']['message']
	except:
		data['event'] = hit['_source']['message']
	try:
		date = hit['_source']['systemTime']
		date = datetime.datetime.utcfromtimestamp(date).strftime('%Y-%m-%d %H:%M:%S')
	except:
		date = formatDate(hit['_source']['event']['timestamp'])
	data['date'] = date
	return data



def getIndices(url, type_):
	global time_query
	headers = {
		'Content-Type': 'application/json',
	}
	events = []
	response = requests.post(url, headers=headers, data=time_query).json()
	#print(json.dumps(response, indent=2))
	for hit in response['hits']['hits']:
		if type_ == "syslog":
			events.append(parseSyslog(hit))
		elif type_ == "firewall":
			events.append(parseFirewall(hit))
		elif type_ == "ids":
			events.append(parseIDS(hit))
		elif type_ == "osquery":
			events.append(parseOSquery(hit))
		else:
			events.append(parseOSSEC(hit))
	return list(filter(None,events))

sock = socket.socket()
host = '192.168.1.4'
port = 12345
sock.connect((host, port))

aborted = False

for i in range(0,len(types)):
	if aborted:
		break
	try:
		print(f"http://localhost:9200/so-{types[i]}*/_search?size=1000 (type {types[i]})")
		events = getIndices(f"http://localhost:9200/so-{types[i]}*/_search?size=1000",types[i])
		sendData(sock, f"TYPE: {types[i]}")
		print(f"Sending {len(events)} {types[i]} events")
		print(f"Received {sock.recv(1024).decode()}")
		for e in events:
			sendData(sock, json.dumps(e))
			r = sock.recv(1024)
			if r == "ABORT":
				aborted = True
				break
		sendData(sock, "done")
	except Exception as e:
		traceback.print_exc()
		exit()

if not aborted:
	time.sleep(0.5) # wait for the server
	sendData(sock, "complete")
	time.sleep(0.5) # let the server finish up
	sock.recv(1024)
sock.close

