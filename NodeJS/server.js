var express = require('express');
var app = express();

app.get('/mngm', function (req, res) {
  res.send('false');
});

app.listen(3000, function () {
  console.log('Example app listening on port 3000!');
});
