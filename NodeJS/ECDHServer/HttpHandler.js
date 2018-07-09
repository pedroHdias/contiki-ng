var http = require("http");

//var options = {};
//var requestData = {};


module.exports = {
	ConfigureBSServer: function (ep, BSKey, LeshanKey) {
		console.log("ConfigureBSServer");

		//ConvertToHex eg. 5838E1D31E262774 -> 35383338453144333145323632373734
		//console.log(BSKey);
		var hexBSKey = Buffer.from(BSKey.toUpperCase(), 'utf8').toString('hex');
		var hexLeshanKey = Buffer.from(LeshanKey.toUpperCase(), 'utf8').toString('hex');
		//console.log(hexBSKey);


		//Convert to Binary
		//var BSKeyBin = new Buffer("" + hexBSKey, "hex");//.toJSON();
		var BSKeyBin = Array.prototype.slice.call(    new Buffer("" + hexBSKey, "hex")  , 0)
		console.log("BSKey");
		//console.log(BSKey);
		//console.log(BSKeyBin);
		//Convert to Binary
		//console.log(LeshanKey);
		//var LeshanKeyBin = new Buffer("" + hexLeshanKey, "hex");//.toJSON();

		var LeshanKeyBin = Array.prototype.slice.call(    new Buffer("" + hexLeshanKey, "hex")   , 0)
		console.log("LeshanKeyBin");
		//console.log(LeshanKey);
		//console.log(LeshanKeyBin);

		//Request 
		var requestData1 = {
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
						"uri": "coaps://[fd00::1]:5684",
						"bootstrapServer": "False",
						"securityMode": "PSK",
						"publicKeyOrId": [79, 117, 114, 73, 100, 101, 110, 116, 105, 116, 121],//#represenation of "OurIdentity"
						"serverPublicKey": [],
						"secretKey": LeshanKeyBin, // [112, 114, 105, 118, 97, 116, 101, 95, 107, 101, 121], //#binary representation of "private_key", the hexa value is 707269766174655f6b6579
						"smsSecurityMode": "NO_SEC",
						"smsBindingKeyParam": [],
						"smsBindingKeySecret": [],
						"serverSmsNumber": "",
						"serverId": 123,
						"clientOldOffTime": 1
					},
					"1": {
						"uri": "coaps://[fd00::1]:5685",
						"bootstrapServer": "True",
						"securityMode": "PSK",
						"publicKeyOrId": [79, 117, 114, 73, 100, 101, 110, 116, 105, 116, 121],//#represenation of "OurIdentity"
						"serverPublicKey": [],
						"secretKey": BSKeyBin , // [112, 114, 105, 118, 97, 116, 101, 95, 107, 101, 121], //#binary representation of "private_key", the hexa value is 707269766174655f6b6579
						"smsSecurityMode": "NO_SEC",
						"smsBindingKeyParam": [],
						"smsBindingKeySecret": [],
						"serverSmsNumber": "",
						"serverId": 911,
						"clientOldOffTime": 20
					}
				}
		}
		//Define options
		var options1 = {
			hostname: 'localhost',
			port: 8090,
			path: '/api/bootstrap/' + ep,
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'text/plain',
			}
		};


		//console.log("options1");
		//console.log(options1);

		console.log("requestData1");
		//console.log(requestData1);

		var req = http.request(options1, function (res) {
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
		req.write(JSON.stringify(requestData1));
		req.end();

		
	},
	ConfigureLeshanServer: function (ep, LeshanKey) {
		//ConvertToHex eg. 5838E1D31E262774 -> 35383338453144333145323632373734
		var Keyhex =  Buffer.from(LeshanKey, 'utf8').toString('hex');
		
		//var LeshanKeyBin 

		//Request 
		requestData = { "endpoint": "" + ep, "psk": { "identity": "OurIdentity", "key": "" + Keyhex } }

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
	}
}

//var httpHandler = require("./HttpHandler");

//httpHandler.ConfigureBSServer("ep","85133eed617242a7","f4v2dzwyw58b6t4ah0lhumcxr" );

//httpHandler.ConfigureLeshanServer("ep","f4v2dzwyw58b6t4ah0lhumcxr");





