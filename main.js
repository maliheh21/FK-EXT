var t = 5;
var n = 10;
var PI = new Array();
var shares = ['80121e68e588ad46c36695f60c894a70a82a6', '0', '80321202023bf1f85adb89158df5fa3d93312', 
	            '8048ef4a7772e5a59e8d70535a975c5db8200', '805138443a63a0932bd82b3fbdae5d35f7a76', 
	            '8068441a4e199d19f0f3ce0350970cf41d337', '807a27070949f16d673bd3a08d4b42c50c0ce', 
	            '8081ccddd099f01e3775de1435b8875c55f62'];
var r = 'd3161558ed9579d2654a87f3a6cc4a14934e36c86ce59323c9ce7f12388c62f8';
var hash_of_r = hashFunction(r);

SERVERIP = "164.111.225.75";
SERVERPORT = 25012;
WEBSERVERIP = "164.111.225.75";
WEBSERVERPORT = 25006;
CLIENTIP = "164.111.225.75";
CLIENTPORT = 25008;
DEVICEIP = "127.0.0.1";
DEVICEPORT = 25010;


function string2ArrayBuffer(string, callback) {
    var bb = new BlobBuilder();
    bb.append(string);
    var f = new FileReader();
    f.onload = function(e) {
        callback(e.target.result);
    }
    f.readAsArrayBuffer(bb.getBlob());
}



function arrayBuffer2String(buf, callback) {
    var bb = new BlobBuilder();
    bb.append(buf);
    var f = new FileReader();
    f.onload = function(e) {
        callback(e.target.result)
    }
    f.readAsText(bb.getBlob());
}



// From https://developer.chrome.com/trunk/apps/app_hardware.html
var str2ab=function(str) {
  var buf=new ArrayBuffer(str.length);
  var bufView=new Uint8Array(buf);
  for (var i=0; i<str.length; i++) {
    bufView[i]=str.charCodeAt(i);
  }
  return buf;
}

// From https://developer.chrome.com/trunk/apps/app_hardware.html
var ab2str=function(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}; 
function parseHexString(str) { 
    var result = [];
    while (str.length >= 8) { 
        result.push(parseInt(str.substring(0, 8), 16));

        str = str.substring(8, str.length);
    }

    return result;
}

function createHexString(arr) {
    var result = "";
    var z;

    for (var i = 0; i < arr.length; i++) {
        var str = arr[i].toString(16);

        z = 8 - str.length + 1;
        str = Array(z).join("0") + str;

        result += str;
    }

    return result;
}



function hashFunction(str) {

	if (str == "abcdefghijklmno") {
		hashRes = new Clipperz.Crypto.ECC.BinaryField.Point({
		x: new Clipperz.Crypto.ECC.BinaryField.Value('0000000005157E4295D6FF0C5B3D9D00FA1B0D76A04ADBF90252C748B2C46850BDCF32AFBF9C5AAB', 16),
		y: new Clipperz.Crypto.ECC.BinaryField.Value('0000000002A28F1B83177FAC4824222D412B691FA51524DF126D535AFF08BB739A9F304A236397AF', 16)
		});	}
	else if (str == "abcdefghijklmnopqrstuvwxyzabcde")  { //S_i id 
		hashRes = new Clipperz.Crypto.ECC.BinaryField.Point({
		x: new Clipperz.Crypto.ECC.BinaryField.Value('00000000060883ADE578F697250191F30EB2F4094732BB667D7D90AEB0C6AB30EC9AC49D96EB54C8', 16),
		y: new Clipperz.Crypto.ECC.BinaryField.Value('000000000100886D599FEB046E1F19682446D3D2870CB2712B6C4432B0D420443F6CDA67C42F2E2D', 16)
		});
	}
	else if (str == "d3161558ed9579d2654a87f3a6cc4a14934e36c86ce59323c9ce7f12388c62f8") { //r = H(pwd, H'(pwd)^k)
		hashRes = new Clipperz.Crypto.ECC.BinaryField.Point({
		x: new Clipperz.Crypto.ECC.BinaryField.Value('00000000060883ADE578F697250191F30EB2F4094732BB667D7D90AEB0C6AB30EC9AC49D96EB54C8', 16),
		y: new Clipperz.Crypto.ECC.BinaryField.Value('000000000100886D599FEB046E1F19682446D3D2870CB2712B6C4432B0D420443F6CDA67C42F2E2D', 16)
		});
	}
	// else if (str = "") {
		// return "1234";
	// }
	return hashRes;
}

 function subOPRF(k, point) {
 	
	curve = Clipperz.Crypto.ECC.StandardCurves.B283();
	value = new Clipperz.Crypto.ECC.BinaryField.Value(k, 16);
	oprfRes = curve.multiply(value, point);
	
	return  oprfRes;
 }
 
// OPRF = F_k(x) = H(x, H'(x)^k)
function oprfEncoded(key, point) {
	return CryptoJS.SHA256(encodePoint(point) + multy(key, point));
}
 
 
// multy(x) = x^k
function multy(key, point) {
	curve = Clipperz.Crypto.ECC.StandardCurves.B283();
	value = new Clipperz.Crypto.ECC.BinaryField.Value(k, 16);
	multiplier = curve.multiply(value, point);

	return encodePoint(multiplier);
}
 
 function computeAlpha(password) {
	 ro = "176016c537c83316470ff3a47140ae383fd32d3d4a37654961e4e5c5b42706b90863f75";
	 hash = hashFunction(password);
	 alpha = OPRFK(ro, hash);
	 return encodePoint(alpha);
 }

function decodePoint(pointStr) {
	var splitArray = pointStr.split(',');
	xBigHex = splitArray[0];
	yBigHex = splitArray[1];
	point = new Clipperz.Crypto.ECC.BinaryField.Point({
		x: new Clipperz.Crypto.ECC.BinaryField.Value(xBigHex, 16),
		y: new Clipperz.Crypto.ECC.BinaryField.Value(yBigHex, 16)
	});	
	return point;
}
function encodePoint(point) {
	pointStr = point.x().toString(16)+","+point.y().toString(16);
	return pointStr;
}


function initialization(password) {
	var serverSocket;
	var clientSocket;
	
	// var key = secrets.random(128);
	var rwd = "5701a4ffee748ba482b77a70967ebb23e5fe1529f80ae24b41a53dfdd55e8e8dee07f5f3745753808360405eae312e5bb8531a1084bc30c2ad43aa3d96c505edbe7a5b9cd452b6";
	console.log("secret: " + rwd.sub);

	// split into 10 shares with a threshold of 5
	var shares = secrets.share(rwd, n, t); 
	// => shares = ['801xxx...xxx','802xxx...xxx','803xxx...xxx','804xxx...xxx','805xxx...xxx']
	console.log(shares);
	
	chrome.socket.create('udp', null, function(createInfo){
    serverSocket = createInfo.socketId;

	    chrome.socket.bind(serverSocket, '127.0.0.1', 25008, function(result){
	        console.log('chrome.socket.bind: result = ' + result.toString());
	    });
	
	    function read()
	    {
	        chrome.socket.recvFrom(serverSocket, 25008, function(recvFromInfo){
	            console.log('Server: recvFromInfo: ', recvFromInfo.port.toString(), 'Message: ', 
	                ab2str(recvFromInfo.data));
	            if(recvFromInfo.resultCode >= 0)
	            {
	            	PI[1] = ab2str(recvFromInfo.data);
	            	f_1 = new BigInteger(OPRFK(PI[1], hash_of_r), 16);
	            	shares_1 = new BigInteger(shares[1], 16);
	            	CI[1] = shares_1.bnXor(f_1);
	            	console.log("CI:" + CI[1]);
	                chrome.socket.sendTo(serverSocket, 
	                	str2ab(shares[1]), 
	                    recvFromInfo.address, recvFromInfo.port, function(){});
	                    /*
	                    str2ab('Received message from client ' + recvFromInfo.address + 
	                    ':' + recvFromInfo.port.toString() + ': ' + 
	                    ab2str(recvFromInfo.data))
	                     */
	                read();
	            }
	            else
	                console.error('Server read error!');
	        });
	    }
	
	    read();
	});
}

function keyExchange(password) {
	
	var serverSocket;
	var clientSocket;

	chrome.socket.create('udp', null, function(createInfo){
    	serverSocket = createInfo.socketId;

    chrome.socket.bind(serverSocket, '127.0.0.1', 25008, function(result){
        console.log('chrome.socket.bind: result = ' + result.toString());
    });

    function read()
    {
        chrome.socket.recvFrom(serverSocket, 25008, function(recvFromInfo){
            console.log('Server: recvFromInfo: ', recvFromInfo.port.toString(), 'Message: ', 
                ab2str(recvFromInfo.data));  	        	

            if(recvFromInfo.resultCode >= 0)
            {
            	var shares_i = ab2str(recvFromInfo.data);
            	var  x = new BigInteger(shares_i, 16);
            	var y = x.toString(16);
            	// var shares_i = TextDecoder([utfLabel = "utf-8"]).decode(recvFromInfo.data);
            	
	            shares[1] = y;
	            
	            console.log(shares); 

	            var comb = secrets.combine( shares.slice(1,6) );
	            console.log(comb); 
                
                chrome.socket.sendTo(serverSocket, 
                    str2ab('Received message from client ' + recvFromInfo.address + 
                    ':' + recvFromInfo.port.toString() + ': ' + 
                    ab2str(recvFromInfo.data)), 
                    recvFromInfo.address, recvFromInfo.port, function(){});
                read();
            }
            else
                console.error('Server read error!');
        });
    }

    read();
});
}

function OPRF(input, IP, Port) {
	
	var deviceSocket;
	var clientSocket;
	
	rho = new BigInteger("176016c537c83316470ff3a47140ae383fd32d3d4a37654961e4e5c5b42706b90863f75", 16); //random \rho
	hashOfX = hashFunction(input);
	console.log(hashOfX.x().asString(16));
	alpha = multy(rho, hashOfX);
	

		
	// A client
	chrome.socket.create('udp', null, function(createInfo){
    clientSocket = createInfo.socketId;

    chrome.socket.connect(clientSocket, IP, Port, function(result){
        console.log('chrome.socket.connect: result = ' + result.toString());
    });
	
    chrome.socket.write(clientSocket, str2ab(alpha), function(writeInfo){
        console.log('writeInfo: ' + writeInfo.bytesWritten + 
            'byte(s) written.');
    });

    chrome.socket.read(clientSocket, 1024, function(readInfo){
        console.log('Client: received response: ' + ab2str(readInfo.data), readInfo);
        var beta = ab2str(recvFromInfo.data);
	    betaPoint = decodePoint(beta);
	    return betaPoint; 
    });
});
}


chrome.runtime.onMessageExternal.addListener(function(request, sender, sendResponse) {
	// console.log(request.message1);
	password = request.message1;
	hashOfX = hashFunction(input);

	
	key = "123456789abcdef03456789abcdef012"; //just for matching, otherwise not required hre
	q =  new BigInteger("38853377844514581418389238136470378132848129621884524445545982633850221" ,16); //q
		 
	// init: rwd = OPRFK(key, hashOfPwd); random r is secret shared random k_i for each server, each server gets ei xor f_k_i(rwd), k= f_r(0)
	// rwd = 
	// var shares = secrets.share(r, n, t);
	
	beta = OPRF(password, DEVICEIP, DEVICEPORT);
	
	roInverse = ro.modInverse(q);
	rwd_prime = CryptoJS.SHA256(pwd + multi(roInverse, beta));
	rwd = CryptoJS.SHA256(pwd + multi(key, hashOfPwd));
	
	if (rwd == rwd_prime) {
		console.log("received rwd is correct!");
	}
	
	hashOfRwd = hashFunction(rwd_prime);
	alpha = multy(rho, hashOfRwd);
	beta = OPRF(rwd_prime, SERVERIP, SERVERPORT);
	
	f_ki_rwd_prime = CryptoJS.SHA256(rwd_prime + multi(roInverse, beta));
	f_ki_rwd = CryptoJS.SHA256(rwd + multi(key, hashOfRwd));
	
	// xorRes = q.xor(ro);
		// var hash = CryptoJS.SHA256("abcdefghijklmno3885337784451458141838923813647037813284812962188452444554598263385022138853377844514581418389238136470378132848129621884524445545982633850221");
		// var comb = secrets.combine(shares.slice(1,6));


	//initialization(hashOfPwd);
	//console.log(rwd.x().asString(16));
	//getKeyfromDevice(password);
	// keyExchange(password);   
	// sendResponse({share: shares[1]}); //"Good bye!"
});





	