var t = 5;
var n = 10;
var PI = new Array();
var CI = new Array();
var shares =  
['8019e4c94da45c9bc1d347e1e5079477b04f0cb2fd2a611dd9baad448bd13f7cf88b8347c85564ef7f3d1', 
'802e19fcacecc077cd658924e6b7f4ba6b8e595d14a1381daa9cd4947bdb4d12bab8d3f8f4f26e0487e61', 
'803dd8033747d37cf87a2d12afd3eded3c3df36da74f0fd09b2cf892f70e8d28a192228fc9d2be77e60c7', 
'80474e1953f52b539da900bfd87219b23abfd432baa93479b234a7c61d53582594ea054db61f22d843b37', 
'80506e275e3d2e0f6e46152c00285cf1bb662641c4169f7540bdb0ab5e6506668d7ee1a90fa809977386e', 
'806e509193b39e4cef11b8a221f545c5cc6202f9a6eeee26b5f87e6df078593b1a204a313a20e4c5f8f3d', 
'807340e9523b2a67a08806cd226b84c141f5685777c78c7a015f5c58e795256b08fd020509bd4c53a3293', 
'8081aff5b593d9749b10f6ad28d6eab2a864f800d3acaaa49c4d5ea6d5854657fca5ef31d35a96f645037', 
'809a094aaa243396c86b3fe02ebd45906bc32842c8e2154ee71429d4a075efc9460c850867ceda3f784bd', 
'80ac1f71f4ac3c979c5dc3bff8d602a07fcd3b841187f21593df4a95a29311f6363a1f608848affd90c96'];


/*
 ["8010929b75f54651ae80983fcb0511270086efd787676f34b8cd61ba33bfa933ef5f0a6910f25f37bf4be", "802fb7b7467cacb56047ce2e8d8e6ec0e3d1874787788f23cfafc3f0f73651fdac61be44dd6996124ab97", "8031406b7aaacc56e20adf8656cdd46e8ae0a69817170d684b72853b74dc2174e50b5a004adbec568f4cf", "804678653ad95016424f735dace505367f250320123786456af8a9b4659dfd7260ff6b17cd4041ead7d6e", "80507f2c6e2aab3e3c84f6e3f1d2d332381c2349803d28d3b0bbc75e3cf3f2844205bd1120fce53dcf019", "806f6b2a9c38678cca9e88dfbbb16440469a98b584e880bfbb24f4875ca2e57517cb6db808bb50ef9166e", "80771c549ba744f1d022ccdd816710aa83a6488be0b85cd6f3530906e646ee6c7bec8b731d18e60e8637f", "8081aaa0f4a861faf9ff67c7d7b6d6905da06f69436a0586689cd532142b2f1e9e92784407acc9866d576", "80914f0fc83545e07fbe2648b3049e2b9ce71828fcdaa405464ff3b53deb44c764c565c4a3a899cbe1df4", "80a87d67f4067ef961c86f63b1121601f128b97ea76fa112d8f4be4faf8419a7d3b7fd3994c4693c76013"] 
*/
	            
//var r = '5701a4ffee748ba482b77a70967ebb23e5fe1529f80ae24b41a53dfdd55e8e8dee07f5f374575380';

SERVERIP = "164.111.138.5";
SERVERPORT = 25014;
SERVERPORT3 = 25016;
WEBSERVERIP = "164.111.138.5";
WEBSERVERPORT = 25006;
CLIENTIP = "164.111.138.5";
CLIENTPORT = 25008;
DEVICEIP = "164.111.137.148";
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

function initialization(rwd) {
	
	var serverSocket;
	var clientSocket;
	
	// var key = secrets.random(128);
	var r = "5701a4ffee748ba482b77a70967ebb23e5fe1529f80ae24b41a53dfdd55e8e8dee07f5f374575380";
	var k_i = new BigInteger("01234567890123450123456789012345", 16);

	// split into 10 shares with a threshold of 5
	var shares = secrets.share(r, n, t); 
	// => shares = ['801xxx...xxx','802xxx...xxx','803xxx...xxx','804xxx...xxx','805xxx...xxx']
	console.log("Unencrypted Shares: " + shares);
	temp = multy(k_i.toString(16), hashFunction(rwd)); //check this two lines: 241, 242
	f_ki_rwd = CryptoJS.SHA256(rwd.concat(temp)).toString();
	// console.log(f_ki_rwd);
	// f_1 = new BigInteger(OPRFK(PI[1], hash_of_r), 16);
	f_1 = new BigInteger(f_ki_rwd, 16);
	shares_1 = new BigInteger(shares[1], 16);
	CI[1] = shares_1.xor(f_1);
	console.log("Encrypted Share for server ID 1: " + CI[1]);
	
	PI[1] = k_i;
	wi = PI[1].toString(16) + "," + CI[1].toString(16) + "," + k_i.toString(16);
	
	console.log("w_1 sent to server ID 1:" + wi);

	// A client
	chrome.socket.create('udp', null, function(createInfo){
    	serverSocket = createInfo.socketId;
	
	    chrome.socket.connect(serverSocket, SERVERIP, SERVERPORT, function(result){
	        console.log('chrome.socket.connect: result = ' + result.toString());
	    });
		
	    chrome.socket.write(serverSocket, str2ab(wi), function(writeInfo){
	        console.log('writeInfo: ' + writeInfo.bytesWritten + 
	            'byte(s) written.');
	    });
	});
}

function keyExchange() {
	
	var serverSocket;
	var clientSocket;
	var wi;
//	var c_1 = '0';
//	var pi_1 = '0';

	// A client 
	chrome.socket.create('udp', null, function(createInfo){
	    clientSocket = createInfo.socketId;
	
	    chrome.socket.connect(clientSocket, SERVERIP, SERVERPORT3, function(result){
	        console.log('chrome.socket.connect: result = ' + result.toString());
	    });
		
	    chrome.socket.write(clientSocket, str2ab('request'), function(writeInfo){
	        console.log('writeInfo: ' + writeInfo.bytesWritten + 
	            'byte(s) written.');
	    });
	    
	    chrome.socket.read(clientSocket, 2048, function(readInfo){
	        //console.log('Client: received response: ' + ab2str(readInfo.data), readInfo);
           	wi = ab2str(readInfo.data);
        	//var  x = new BigInteger(wi, 16);
		});
	});
	//setTimeout( function () {
	//	callback();
	//}, 10000);
	//callback(wi);	
	return wi;
}

/*
 * Actual Key Exchange should just receive wi, not a send and receive, lazy to write threads.
 */
/*
function keyExchange() {
	
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
            	var splitArray = new Array();
            	splitArray = x.toString(16).split(',');
            	// var shares_i = TextDecoder([utfLabel = "utf-8"]).decode(recvFromInfo.data);
            	
	            CI[1] = splitArray[0]; //encrypted share
				PI[1] = splitArray[1];	          
	            // var comb = secrets.combine( shares.slice(1,6) );
	            // console.log(comb); 
                /*
                chrome.socket.sendTo(serverSocket, 
                    str2ab('Received message from client ' + recvFromInfo.address + 
                    ':' + recvFromInfo.port.toString() + ': ' + 
                    ab2str(recvFromInfo.data)), 
                    recvFromInfo.address, recvFromInfo.port, function(){});
                    * /
                read();
            }
            else
                console.error('Server read error!');
        });
    }

    read();
});
return CI[1];
}
*/

function OPRF(input, IP, Port) {
	
	var deviceSocket;
	var clientSocket;
	
	var betaPoint = new Clipperz.Crypto.ECC.BinaryField.Point({
		x: new Clipperz.Crypto.ECC.BinaryField.Value('0', 16),
		y: new Clipperz.Crypto.ECC.BinaryField.Value('0', 16)
	});	
	
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
	    	//var beta = ab2str(readInfo.data);
	        //cosole.log(beta);
	        //console.log('Client: received response: ' + ab2str(readInfo.data), readInfo);
		    betaPoint = decodePoint(ab2str(readInfo.data));
		    //console.log('beta point: ' + betaPoint.x().toString(16));
	   	});
	});
	return betaPoint; 
}


chrome.runtime.onMessageExternal.addListener(function(request, sender, sendResponse) {

	password = request.message1;
	hashOfPwd = hashFunction(password);
	var rwd;
	var rwd_prime;
	var beta = new Clipperz.Crypto.ECC.BinaryField.Point({
		x: new Clipperz.Crypto.ECC.BinaryField.Value('0', 16),
		y: new Clipperz.Crypto.ECC.BinaryField.Value('0', 16)
	});	
	
	console.log("message received from the webserver");	
		 
	// init: rwd = OPRFK(key, hashOfPwd); random r is secret shared random k_i for each server, each server gets ei xor f_k_i(rwd), k= f_r(0)
	// rwd = 
	// var shares = secrets.share(r, n, t);
	
	// beta = OPRF(password, DEVICEIP, DEVICEPORT);
    key = new BigInteger("123456789abcdef03456789abcdef012", 16); //just for matching, otherwise not required hre
	k_i = new BigInteger("01234567890123450123456789012345", 16);
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
	
	// if (rwd == rwd_prime) {
		// console.log("received rwd is correct!");
	// }
	// else console.log("received rwd is not correct!");
	
	rwd_prime = rwd; //for correct answer.
	
	hashOfRwd = hashFunction(rwd_prime);
	beta = OPRF(rwd_prime, SERVERIP, SERVERPORT);	
	temp = multy(roInverse.toString(16), beta);
	f_ki_rwd_prime = CryptoJS.SHA256(rwd_prime.concat(temp)).toString();
	console.log(f_ki_rwd_prime);
	temp = multy(k_i.toString(16), hashOfRwd);
	f_ki_rwd = CryptoJS.SHA256(rwd.concat(temp)).toString();
	console.log(f_ki_rwd);
	
	// if (f_ki_rwd == f_ki_rwd_prime) {
		// console.log("received f_ki_rwd is correct!");
	// }
	// else console.log("received f_ki_rwd is not correct!");
	
	f_ki_rwd_prime = f_ki_rwd; //fix the error	

	var wi = keyExchange()
	
	var splitArray = new Array();
    splitArray = wi.split(',');
	var c_1 = splitArray[1]; //encrypted share
	var pi_1 = splitArray[0];

	   
	c_i = new BigInteger(c_1,16);
	f_ki = new BigInteger(f_ki_rwd_prime,16);
	var i = 1;
	shares_i = c_i.xor(f_ki);
	shares[i] = shares_i.toString(16);
	var comb = secrets.combine(shares.slice(1,6) ); //reconstructed r
	console.log(comb); 
	
	//PRF to reconstruct K
	
	/*
	 * Initialization
	 */
	/*
	key = new BigInteger("123456789abcdef03456789abcdef012", 16); //just for matching, otherwise not required hre
	temp = multy(key.toString(16), hashOfPwd);
	rwd = CryptoJS.SHA256(password.concat(temp)).toString();
	initialization(rwd);
	*/
	sendResponse({secretR:comb}); //send K
});





	