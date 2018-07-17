var http = require("http");




var requestData = {
	"servers": {
		"0":
			{
				"shortId": 123,
				"lifetime": 20,
				"defaultMinPeriod": 1,
				//"defaultMaxPeriod": "None",
				//"disableTimeout": "None",
				"notifIfDisabled": "True",
				"binding": "U"
			}
	},
	"security":
		{
			"0": {
				"uri": "coaps://127.0.0.1:5784",
				"bootstrapServer": "False",
				"securityMode": "PSK",
				"publicKeyOrId": [115, 101, 99, 117, 114, 101, 95, 99, 108, 105, 101, 110, 116, 95, 105, 100],//#represenation of "secure_client_id"
				"serverPublicKey": [],
				"secretKey": [112, 114, 105, 118, 97, 116, 101, 95, 107, 101, 121], //#binary representation of "private_key", the hexa value is 707269766174655f6b6579
				"smsSecurityMode": "NO_SEC",
				"smsBindingKeyParam": [],
				"smsBindingKeySecret": [],
				"serverSmsNumber": "+3343577464",
				"serverId": 123,
				"clientOldOffTime": 1
			},
			"1": {
				"uri": "coap://127.0.0.1:5783",
				"bootstrapServer": "True",
				"securityMode": "PSK",
				"publicKeyOrId": [115, 101, 99, 117, 114, 101, 95, 99, 108, 105, 101, 110, 116, 95, 105, 100], //#binary represenation of "secure_client_id"
				"serverPublicKey": [],
				"secretKey": [112, 114, 105, 118, 97, 116, 101, 95, 107, 101, 121], //#binary representation of "private_key", the hexa value is 707269766174655f6b6579
				"smsSecurityMode": "NO_SEC",
				"smsBindingKeyParam": [],
				"smsBindingKeySecret": [],
				"serverSmsNumber": "+3343577911",
				"serverId": 911,
				"clientOldOffTime": 20
			}
		}
}

var key = new Buffer("707269766174655f6b6579", "hex")
console.log(key.toJSON());




var options = {
	hostname: 'localhost',
	port: 8090,
	path: '/api/bootstrap/clientendpoint',
	method: 'POST',
	headers: {
		'Content-Type': 'application/json',
		'Accept': 'text/plain',
	}
  //body: JSON.stringify(requestData)
};
var req = http.request(options, function (res) {
	console.log('Status: ' + res.statusCode);
	console.log('Headers: ' + JSON.stringify(res.headers));
	res.setEncoding('utf8');
	res.on('data', function (body) {
		console.log('Body: ' + body);
	});
});
req.on('error', function (e) {
	console.log('problem with request: ' + e.message);
});

// write data to request body
req.write(JSON.stringify(requestData));
req.end();
