var coap        = require('coap')
  , server      = coap.createServer({ type: 'udp6' })
  , httpHandler = require("./HttpHandler");

//ECC
const BN = require('bn.js');
var EC = require('elliptic').ec;
var ec = new EC('p192');
var pad = require('pad-left');

//hash para guardar chaves!
var hash = new HashTable(); 


//Martelar chaves do server
//Define os pontos publicos
var OwnX = '11FA2B68851DEDA9B0CE4D6EFD76F4623DD4600FEB5824EF';
var OwnY = '1B2585D62B7E6055C8534362A55F7F4F6EAB50F376CF18CE';
//Gera chave
var OwnPubKey = { x: OwnX.toString('hex'), y: OwnY.toString('hex') };
//Faz o par de chaves
var OwnKeyPair = ec.keyFromPublic(OwnPubKey, 'hex');
//define chave privada
OwnKeyPair.priv = new BN('A722747CCF51EB381BA75A75A74DF4EB31633C852E0D97EE',16);



server.on('request', function(req, res) {
	let response = req._packet.payload.toString('utf8');
	
	console.log(req.url);
	
	var arrURL = req.url.split('?')
	
	var path = arrURL[0];
	var ep = arrURL[1].split('=')[1];
	//Devia validar se o array tem posição 0
	
	//valida se existe no hash
	var hasItem = hash.hasItem(ep);
	if(!hasItem){
		hash.setItem(ep,{pointX: '' , pointY:''})
	}
	//Vai buscar Item para actualizar
	var item = hash.getItem(ep);

	if(path == '/ecdh/puby'){
		item.pointY=response.split(';')[0];
  	res.end('Ypoint='+OwnY+'\n')
  	console.log(item.pointY);
	}else if(path == '/ecdh/pubx'){ 
		item.pointX=response.split(';')[0];
  	res.end('Xpoint='+OwnX+'\n')
	}else{
		//mandar erro!!!
	}
	
	//actuliza hash
	hash.setItem(ep,item);

	//Validar se já pode fazer post para o BSserver (eventualmente fazer um evento para validar se já foi configurado, adicionar um bit à estrutura com o estado)
	if(item.pointX != '' && item.pointY != ''){
        var BSServerSharedkey = SetSharedKey(item);
        var LeshanSharedkey = Math.random().toString(36).substring(2);

        httpHandler.ConfigureBSServer(ep,BSServerSharedkey,LeshanSharedkey);
        httpHandler.ConfigureLeshanServer(ep,LeshanSharedkey);
	}
	
	
	console.log('Recebeu	');
})


server.listen(5686,'fd00::1', function() {
 	console.log('server started');
})


function SetSharedKey(item){

	//var item = hash.getItem(ep);

	var pubB = { x: item.pointX.toString('hex'), y: item.pointY.toString('hex') };         // case 2
	var key2 = ec.keyFromPublic(pubB);

	/*
	console.log(pubA.x);
	console.log(pubA.y);
	console.log(pubB.x);
	console.log(pubB.y);
	*/

	//key2.priv = new BN('29E06280060308049FF35541CCFC1156BCCB2EE1E97FE3517B3AA4588F26EB8E',16);

	var shared1 = OwnKeyPair.derive(key2.getPublic());

  console.log(OwnKeyPair);
  console.log(key2);
	console.log(key2.getPublic().getX());
	console.log(key2.getPublic().getY());
  //gera chave partilhada
  var shared1 = OwnKeyPair.derive(key2.getPublic());
  console.log("Partilhada "+ shared1.toString(16));


	
	//console.log('sharedBig: ' + shared1);
	
	shared1 = pad(  shared1.toString(16), 24, '0')
	
  var res = shared1.toString(16).match(/.{2}/g);
  var final = ""
  res.reverse().forEach(function(entry, idx, array) {
      if(idx <8)
      final += entry;
  });
  
  //Fazer post
  
	console.log(final);
    return final;
}




function HashTable(obj)
{
    this.length = 0;
    this.items = {};
    for (var p in obj) {
        if (obj.hasOwnProperty(p)) {
            this.items[p] = obj[p];
            this.length++;
        }
    }

    this.setItem = function(key, value)
    {
        var previous = undefined;
        if (this.hasItem(key)) {
            previous = this.items[key];
        }
        else {
            this.length++;
        }
        this.items[key] = value;
        return previous;
    }

    this.getItem = function(key) {
        return this.hasItem(key) ? this.items[key] : undefined;
    }

    this.hasItem = function(key)
    {
        return this.items.hasOwnProperty(key);
    }
   
    this.removeItem = function(key)
    {
        if (this.hasItem(key)) {
            previous = this.items[key];
            this.length--;
            delete this.items[key];
            return previous;
        }
        else {
            return undefined;
        }
    }

    this.keys = function()
    {
        var keys = [];
        for (var k in this.items) {
            if (this.hasItem(k)) {
                keys.push(k);
            }
        }
        return keys;
    }

    this.values = function()
    {
        var values = [];
        for (var k in this.items) {
            if (this.hasItem(k)) {
                values.push(this.items[k]);
            }
        }
        return values;
    }

    this.each = function(fn) {
        for (var k in this.items) {
            if (this.hasItem(k)) {
                fn(k, this.items[k]);
            }
        }
    }

    this.clear = function()
    {
        this.items = {}
        this.length = 0;
    }
}
