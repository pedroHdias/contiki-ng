var http = require("http");



//Tem de converter para hexa
var requestData = {"endpoint":"Endpoit","psk":{"identity":"ident","key":"34534534534534"}}





var options = {
	hostname: 'localhost',
	port: 8080,
	path: '/api/security/clients/',
	method: 'PUT',
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
