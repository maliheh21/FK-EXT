var t = 5;
var n = 10;
var PI = new Array();
var shares = ['80121e68e588ad46c36695f60c894a70a82a6', '0', '80321202023bf1f85adb89158df5fa3d93312', 
	            '8048ef4a7772e5a59e8d70535a975c5db8200', '805138443a63a0932bd82b3fbdae5d35f7a76', 
	            '8068441a4e199d19f0f3ce0350970cf41d337', '807a27070949f16d673bd3a08d4b42c50c0ce', 
	            '8081ccddd099f01e3775de1435b8875c55f62'];
var r = 'd3161558ed9579d2654a87f3a6cc4a14934e36c86ce59323c9ce7f12388c62f8';
var hash_of_r = hashFunction(r);

SERVERIP = "192.168.1.153";
SERVERPORT = 25012;
WEBSERVERIP = "192.168.1.153";
WEBSERVERPORT = 25006;
CLIENTIP = "192.168.1.153";
CLIENTPORT = 25008;
DEVICEIP = "192.168.1.159";
DEVICEPORT = 25010;


var STR_PAD_LEFT = 1;
var STR_PAD_RIGHT = 2;
var STR_PAD_BOTH = 3;

function pad(str, len, pad, dir) {

    if (typeof(len) == "undefined") { var len = 0; }
    if (typeof(pad) == "undefined") { var pad = ' '; }
    if (typeof(dir) == "undefined") { var dir = STR_PAD_RIGHT; }

    if (len + 1 >= str.length) {

        switch (dir){

            case STR_PAD_LEFT:
                str = Array(len + 1 - str.length).join(pad) + str;
            break;

            case STR_PAD_BOTH:
                var right = Math.ceil((padlen = len - str.length) / 2);
                var left = padlen - right;
                str = Array(left+1).join(pad) + str + Array(right+1).join(pad);
            break;

            default:
                str = str + Array(len + 1 - str.length).join(pad);
            break;

        } // switch

    }

    return str;

}

function string2ArrayBuffer(string, callback) {
    var bb = new BlobBuilder();
    bb.append(string);
    var f = new FileReader();
    f.onload = function(e) {
        callback(e.target.result);
    };
    f.readAsArrayBuffer(bb.getBlob());
}



function arrayBuffer2String(buf, callback) {
    var bb = new BlobBuilder();
    bb.append(buf);
    var f = new FileReader();
    f.onload = function(e) {
        callback(e.target.result);
    };
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
};

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
	else if (str == "d6a71405bdcc0d3b2b26a6e8e6977ba1e55532bb2e54c03df1b35318623d4427") { //r = H(pwd, H'(pwd)^k)
		hashRes = new Clipperz.Crypto.ECC.BinaryField.Point({
		x: new Clipperz.Crypto.ECC.BinaryField.Value('060883ADE578F697250191F30EB2F4094732BB667D7D90AEB0C6AB30EC9AC49D96EB54C8', 16),
		y: new Clipperz.Crypto.ECC.BinaryField.Value('0100886D599FEB046E1F19682446D3D2870CB2712B6C4432B0D420443F6CDA67C42F2E2D', 16)
		});
	}
	else {
		hashRes = new Clipperz.Crypto.ECC.BinaryField.Point({
		x: new Clipperz.Crypto.ECC.BinaryField.Value('0', 16),
		y: new Clipperz.Crypto.ECC.BinaryField.Value('0', 16)
		});	
	}
	return hashRes;
}

 function subOPRF(k, point) {
 	
	curve = Clipperz.Crypto.ECC.StandardCurves.B283();
	value = new Clipperz.Crypto.ECC.BinaryField.Value(k, 16);
	oprfRes = curve.multiply(value, point);
	
	return  oprfRes;
 }
 
// OPRF = F_k(x) = H(x, H'(x)^k)
function oprfEncoded(k, point) {
	return CryptoJS.SHA256(encodePoint(point) + multy(k, point));
}
 
 
// multy(x) = x^k
function multy(k, point) {
		
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
	var splitArray = new Array();
	splitArray = pointStr.split(',');
	xBigHex = splitArray[0];
	yBigHex = splitArray[1];
	
	xBigHex = pad(xBigHex, 80, '0', 1);
	yBigHex = pad(yBigHex, 80, '0', 1);


	point = new Clipperz.Crypto.ECC.BinaryField.Point({
		x: new Clipperz.Crypto.ECC.BinaryField.Value(xBigHex, 16),
		y: new Clipperz.Crypto.ECC.BinaryField.Value(yBigHex, 16)
	});	
	return point;
}
function encodePoint(point) {
	pointStr = point.x().asString(16).concat(',');
	pointStr = pointStr.concat(point.y().asString(16));
	console.log(pointStr);
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
    	clientSocket = createInfo.socketId;

    chrome.socket.bind(clientSocket, CLIENTIP, CLIENTPORT, function(result){
        console.log('chrome.socket.bind: result = ' + result.toString());
    });

    function read()
    {
        chrome.socket.recvFrom(clientSocket, 25008, function(recvFromInfo){
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
                /*
                chrome.socket.sendTo(serverSocket, 
                    str2ab('Received message from client ' + recvFromInfo.address + 
                    ':' + recvFromInfo.port.toString() + ': ' + 
                    ab2str(recvFromInfo.data)), 
                    recvFromInfo.address, recvFromInfo.port, function(){});
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

function OPRF(input, IP, Port) {
	
	var deviceSocket;
	var clientSocket;
	
	rho = "1e3ea1812eb3ef506abae9d87cf580f37edebb21cd2384032527f2ec5c07d94c483562";
	hashOfX = hashFunction(input);
	alpha = multy(rho.toString(16), hashOfX);
	
	console.log("alpha in OPRF" + alpha);

	
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
	    	//beta = ab2str(readInfo.data);
	        //cosole.log(beta);
	        console.log('Client: received response: ' + ab2str(readInfo.data), readInfo);
		    betaPoint = decodePoint(ab2str(readInfo.data));
	   	});
	});
	return betaPoint; 
}


chrome.runtime.onMessageExternal.addListener(function(request, sender, sendResponse) {

	password = request.message1;
	hashOfPwd = hashFunction(password);
	var beta;
	var rwd;
	var rwd_prime;

	console.log("message received from the webserver");
	
	keyExchange(password);
	
		 
	// init: rwd = OPRFK(key, hashOfPwd); random r is secret shared random k_i for each server, each server gets ei xor f_k_i(rwd), k= f_r(0)
	// rwd = 
	// var shares = secrets.share(r, n, t);
	
	// beta = OPRF(password, DEVICEIP, DEVICEPORT);
    key = new BigInteger("123456789abcdef03456789abcdef012", 16); //just for matching, otherwise not required hre
	q =  new BigInteger("1fffffffffffffffffffffffffffffffffff7c81ccb307e49c5480b2d82153e77d6d983" ,16); //q
	rho = new BigInteger("1e3ea1812eb3ef506abae9d87cf580f37edebb21cd2384032527f2ec5c07d94c483562", 16); //random \rho
	roInverse = rho.modInverse(q); //cdca6fc2c0334d81ec178e7e5c5ca05296c304c13e143c2cd86d2468f8ff121d1c7822
	console.log(roInverse.toString(16));
	beta = OPRF(password, DEVICEIP, DEVICEPORT);
    console.log(beta.x().asString(16));
	temp = multy(roInverse.toString(16), beta);
	rwd_prime = CryptoJS.SHA256(password.concat(temp)).toString();
	console.log(rwd_prime);
	temp = multy(key.toString(16), hashOfPwd);
	rwd = CryptoJS.SHA256(password.concat(temp)).toString();
	console.log(rwd);
	
	if (rwd == rwd_prime) {
		console.log("received rwd is correct!");
	}
	else console.log("received rwd is not correct!");
	
	rwd_prime = rwd; //for correct answer.
	
	hashOfRwd = hashFunction(rwd_prime);
	beta = OPRF(rwd_prime, SERVERIP, SERVERPORT);	
	temp = multy(roInverse.toString(16), beta);
	f_ki_rwd_prime = CryptoJS.SHA256(rwd_prime.concat(temp)).toString();
	console.log(f_ki_rwd_prime);
	temp = multy(key.toString(16), hashOfRwd);
	f_ki_rwd = CryptoJS.SHA256(rwd.concat(temp)).toString();
	console.log(f_ki_rwd);
	
	if (f_ki_rwd == f_ki_rwd_prime) {
		console.log("received rwd is correct!");
	}
	else console.log("received rwd is not correct!");
	
	// xorRes = q.xor(ro);
		// var hash = CryptoJS.SHA256("abcdefghijklmno3885337784451458141838923813647037813284812962188452444554598263385022138853377844514581418389238136470378132848129621884524445545982633850221");
		// var comb = secrets.combine(shares.slice(1,6));


	//initialization(hashOfPwd);
	//console.log(rwd.x().asString(16));
	//getKeyfromDevice(password);
	// keyExchange(password);   
	// sendResponse({share: shares[1]}); //"Good bye!"
	sendResponse("Good bye!"); //
});





	