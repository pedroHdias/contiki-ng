var http = require("http");

var options = {};
var requestData = {};


module.exports = {
	ConfigureBSServer: function (ep, BSKey, LeshanKey) {
		//ConvertToHex eg. 5838E1D31E262774 -> 35383338453144333145323632373734

		//Convert to Binary
		var BSKeyBin = new Buffer("" + BSKey, "hex").toJSON();
		console.log(BSKeyBin);
		//Convert to Binary
		var LeshanKeyBin = new Buffer("" + LeshanKey, "hex").toJSON();
		console.log(LeshanKeyBin);

		//Request 
		requestData = {
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
						"uri": "coaps://[fd00::1]:5685",
						"bootstrapServer": "True",
						"securityMode": "PSK",
						"publicKeyOrId": [79, 117, 114, 73, 100, 101, 110, 116, 105,116,121 ],//#represenation of "OurIdentity"
						"serverPublicKey": [],
						"secretKey": BSKeyBin, // [112, 114, 105, 118, 97, 116, 101, 95, 107, 101, 121], //#binary representation of "private_key", the hexa value is 707269766174655f6b6579
						"smsSecurityMode": "NO_SEC",
						"smsBindingKeyParam": [],
						"smsBindingKeySecret": [],
						"serverSmsNumber": "",
						"serverId": 123,
						"clientOldOffTime": 1
					},
					"1": {
						"uri": "coaps://[fd00::1]:5684",
						"bootstrapServer": "False",
						"securityMode": "PSK",
						"publicKeyOrId": [79, 117, 114, 73, 100, 101, 110, 116, 105,116,121 ],//#represenation of "OurIdentity"
						"serverPublicKey": [],
						"secretKey": LeshanKeyBin, // [112, 114, 105, 118, 97, 116, 101, 95, 107, 101, 121], //#binary representation of "private_key", the hexa value is 707269766174655f6b6579
						"smsSecurityMode": "NO_SEC",
						"smsBindingKeyParam": [],
						"smsBindingKeySecret": [],
						"serverSmsNumber": "+3343577911",
						"serverId": 911,
						"clientOldOffTime": 20
					}
				}
		}
		//Define options
		options = {
			hostname: 'localhost',
			port: 8090,
			path: '/api/bootstrap/' + ep,
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'text/plain',
			}
		};
	},
	ConfigureLeshanServer: function (ep, LeshanKey) {
		//ConvertToHex eg. 5838E1D31E262774 -> 35383338453144333145323632373734
		var Keyhex = "";

		//Request 
		requestData = { "endpoint": "" + ep, "psk": { "identity": "Identity", "key": "" + Keyhex } }

		//Define options
		options = {
			hostname: 'localhost',
			port: 8080,
			path: '/api/security/clients/',
			method: 'PUT',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'text/plain',
			}
		}
	}
}



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
