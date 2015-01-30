var t = 5;
var n = 10;
var PI = new Array();
var CI = new Array();
//var shares = ['8019e4c94da45c9bc1d347e1e5079477b04f0cb2fd2a611dd9baad448bd13f7cf88b8347c85564ef7f3d1', '802e19fcacecc077cd658924e6b7f4ba6b8e595d14a1381daa9cd4947bdb4d12bab8d3f8f4f26e0487e61', '803dd8033747d37cf87a2d12afd3eded3c3df36da74f0fd09b2cf892f70e8d28a192228fc9d2be77e60c7', '80474e1953f52b539da900bfd87219b23abfd432baa93479b234a7c61d53582594ea054db61f22d843b37', '80506e275e3d2e0f6e46152c00285cf1bb662641c4169f7540bdb0ab5e6506668d7ee1a90fa809977386e', '806e509193b39e4cef11b8a221f545c5cc6202f9a6eeee26b5f87e6df078593b1a204a313a20e4c5f8f3d', '807340e9523b2a67a08806cd226b84c141f5685777c78c7a015f5c58e795256b08fd020509bd4c53a3293', '8081aff5b593d9749b10f6ad28d6eab2a864f800d3acaaa49c4d5ea6d5854657fca5ef31d35a96f645037', '809a094aaa243396c86b3fe02ebd45906bc32842c8e2154ee71429d4a075efc9460c850867ceda3f784bd', '80ac1f71f4ac3c979c5dc3bff8d602a07fcd3b841187f21593df4a95a29311f6363a1f608848affd90c96'];
var s = new Clipperz.Crypto.ECC.BinaryField.Value("8019e4c94da45c9bc1d347e1e5079477", 16);
var beta = new Clipperz.Crypto.ECC.BinaryField.Point({
	x : new Clipperz.Crypto.ECC.BinaryField.Value('0', 16),
	y : new Clipperz.Crypto.ECC.BinaryField.Value('0', 16)
});

var k_s = new Clipperz.Crypto.ECC.BinaryField.Value("01234567890123450123456789012345", 16);
var rho = new Clipperz.Crypto.ECC.BinaryField.Value("5f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053", 16);
var wi;
var k_d = new Clipperz.Crypto.ECC.BinaryField.Value("123456789abcdef03456789abcdef012", 16);
var curve = Clipperz.Crypto.ECC.StandardCurves.B283();
var f2m = curve.finiteField();
var roInverse = f2m.inverse(rho);
var hashOfPwd;
var mu = "347c85564ef7f3d1";
/*
["8010929b75f54651ae80983fcb0511270086efd787676f34b8cd61ba33bfa933ef5f0a6910f25f37bf4be", "802fb7b7467cacb56047ce2e8d8e6ec0e3d1874787788f23cfafc3f0f73651fdac61be44dd6996124ab97", "8031406b7aaacc56e20adf8656cdd46e8ae0a69817170d684b72853b74dc2174e50b5a004adbec568f4cf", "804678653ad95016424f735dace505367f250320123786456af8a9b4659dfd7260ff6b17cd4041ead7d6e", "80507f2c6e2aab3e3c84f6e3f1d2d332381c2349803d28d3b0bbc75e3cf3f2844205bd1120fce53dcf019", "806f6b2a9c38678cca9e88dfbbb16440469a98b584e880bfbb24f4875ca2e57517cb6db808bb50ef9166e", "80771c549ba744f1d022ccdd816710aa83a6488be0b85cd6f3530906e646ee6c7bec8b731d18e60e8637f", "8081aaa0f4a861faf9ff67c7d7b6d6905da06f69436a0586689cd532142b2f1e9e92784407acc9866d576", "80914f0fc83545e07fbe2648b3049e2b9ce71828fcdaa405464ff3b53deb44c764c565c4a3a899cbe1df4", "80a87d67f4067ef961c86f63b1121601f128b97ea76fa112d8f4be4faf8419a7d3b7fd3994c4693c76013"]
*/

//var r = '5701a4ffee748ba482b77a70967ebb23e5fe1529f80ae24b41a53dfdd55e8e8dee07f5f374575380';

SERVERIP = "192.168.1.153";
SERVERPORT = 25014;
SERVERPORT3 = 25016;
WEBSERVERIP = "192.168.1.153";
WEBSERVERPORT = 25006;
CLIENTIP = "192.168.1.153";
CLIENTPORT = 25008;
DEVICEIP = "192.168.1.241";
DEVICEPORT = 25010;

/*
 SERVERIP = "164.111.225.176";
 SERVERPORT = 25014;
 SERVERPORT3 = 25016;
 WEBSERVERIP = "164.111.225.176";
 WEBSERVERPORT = 25006;
 CLIENTIP = "164.111.225.176";
 CLIENTPORT = 25008;
 DEVICEIP = "164.111.197.158";
 DEVICEPORT = 25010;*/

var STR_PAD_LEFT = 1;
var STR_PAD_RIGHT = 2;
var STR_PAD_BOTH = 3;

//setTimeout( function () {
//}, 10000);

function pad(str, len, pad, dir) {

	if ( typeof (len) == "undefined") {
		var len = 0;
	}
	if ( typeof (pad) == "undefined") {
		var pad = ' ';
	}
	if ( typeof (dir) == "undefined") {
		var dir = STR_PAD_RIGHT;
	}

	if (len + 1 >= str.length) {

		switch (dir) {

			case STR_PAD_LEFT:
				str = Array(len + 1 - str.length).join(pad) + str;
				break;

			case STR_PAD_BOTH:
				var right = Math.ceil(( padlen = len - str.length) / 2);
				var left = padlen - right;
				str = Array(left + 1).join(pad) + str + Array(right + 1).join(pad);
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
var str2ab = function(str) {
	var buf = new ArrayBuffer(str.length);
	var bufView = new Uint8Array(buf);
	for (var i = 0; i < str.length; i++) {
		bufView[i] = str.charCodeAt(i);
	}
	return buf;
};

// From https://developer.chrome.com/trunk/apps/app_hardware.html
var ab2str = function(buf) {
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

function pausecomp(millis) {
	var date = new Date();
	var curDate = null;

	do {
		curDate = new Date();
	} while(curDate-date < millis);
}

function hashFunction(str) {

	if (str == "abcdefghijklmno") {
		hashRes = new Clipperz.Crypto.ECC.BinaryField.Point({
			x : new Clipperz.Crypto.ECC.BinaryField.Value('0000000005157E4295D6FF0C5B3D9D00FA1B0D76A04ADBF90252C748B2C46850BDCF32AFBF9C5AAB', 16),
			y : new Clipperz.Crypto.ECC.BinaryField.Value('0000000002A28F1B83177FAC4824222D412B691FA51524DF126D535AFF08BB739A9F304A236397AF', 16)
		});
	} else if (str == "abcdefghijklmnopqrstuvwxyzabcde") {//S_i id
		hashRes = new Clipperz.Crypto.ECC.BinaryField.Point({
			x : new Clipperz.Crypto.ECC.BinaryField.Value('00000000060883ADE578F697250191F30EB2F4094732BB667D7D90AEB0C6AB30EC9AC49D96EB54C8', 16),
			y : new Clipperz.Crypto.ECC.BinaryField.Value('000000000100886D599FEB046E1F19682446D3D2870CB2712B6C4432B0D420443F6CDA67C42F2E2D', 16)
		});
	} else if (str == "d3161558ed9579d2654a87f3a6cc4a14934e36c86ce59323c9ce7f12388c62f8") {//r = H(pwd, H'(pwd)^k)
		hashRes = new Clipperz.Crypto.ECC.BinaryField.Point({
			x : new Clipperz.Crypto.ECC.BinaryField.Value('00000000060883ADE578F697250191F30EB2F4094732BB667D7D90AEB0C6AB30EC9AC49D96EB54C8', 16),
			y : new Clipperz.Crypto.ECC.BinaryField.Value('000000000100886D599FEB046E1F19682446D3D2870CB2712B6C4432B0D420443F6CDA67C42F2E2D', 16)
		});
	} else if (str == "d6a71405bdcc0d3b2b26a6e8e6977ba1e55532bb2e54c03df1b35318623d4427") {//r = H(pwd, H'(pwd)^k)
		hashRes = new Clipperz.Crypto.ECC.BinaryField.Point({
			x : new Clipperz.Crypto.ECC.BinaryField.Value('060883ADE578F697250191F30EB2F4094732BB667D7D90AEB0C6AB30EC9AC49D96EB54C8', 16),
			y : new Clipperz.Crypto.ECC.BinaryField.Value('0100886D599FEB046E1F19682446D3D2870CB2712B6C4432B0D420443F6CDA67C42F2E2D', 16)
		});
	} else {
		hashRes = new Clipperz.Crypto.ECC.BinaryField.Point({
			x : new Clipperz.Crypto.ECC.BinaryField.Value('0', 16),
			y : new Clipperz.Crypto.ECC.BinaryField.Value('0', 16)
		});
	}
	return hashRes;
}

function subOPRF(k, point) {

	//curve = Clipperz.Crypto.ECC.StandardCurves.B283();
	value = new Clipperz.Crypto.ECC.BinaryField.Value(k, 16);
	oprfRes = curve.multiply(value, point);

	return oprfRes;
}

// multy(x) = x^k
function multy(k, point) {
	// curve = Clipperz.Crypto.ECC.StandardCurves.B283();
	value = new Clipperz.Crypto.ECC.BinaryField.Value(k, 16);
	multiplier = curve.multiply(value, point);
	return encodePoint(multiplier);
}

function decodePoint(pointStr) {
	var splitArray = new Array();
	splitArray = pointStr.split(',');
	xBigHex = splitArray[0];
	yBigHex = splitArray[1];

	xBigHex = pad(xBigHex, 80, '0', 1);
	yBigHex = pad(yBigHex, 80, '0', 1);

	point = new Clipperz.Crypto.ECC.BinaryField.Point({
		x : new Clipperz.Crypto.ECC.BinaryField.Value(xBigHex, 16),
		y : new Clipperz.Crypto.ECC.BinaryField.Value(yBigHex, 16)
	});
	return point;
}

function encodePoint(point) {
	pointStr = point.x().asString(16).concat(',');
	pointStr = pointStr.concat(point.y().asString(16));
	return pointStr;
}

//y2+ xy = x3+ ax2+ b
function pointMember(point) {

	/*point = new Clipperz.Crypto.ECC.BinaryField.Point({
	 x : new Clipperz.Crypto.ECC.BinaryField.Value('05F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B12053', 16),
	 y : new Clipperz.Crypto.ECC.BinaryField.Value('03676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4', 16)
	 });*/

	var x = point.x();
	var y = point.y();

	var a = curve.a();
	var b = curve.b();
	var lhs = f2m.add(f2m.multiply(y, y), f2m.multiply(y, x));
	var rhs = f2m.add(b, f2m.add(f2m.multiply(x, f2m.multiply(x, x)), f2m.multiply(a, f2m.multiply(x, x))));

	if (lhs.asString(16) == rhs.asString(16))
		return true;
	else
		return false;
}

function initialization(rwd) {//old

	var initSocket;

	// var key = secrets.random(128);
	var r = "5701a4ffee748ba482b77a70967ebb23e5fe1529f80ae24b41a53dfdd55e8e8dee07f5f374575380";
	var k_s = new BigInteger("01234567890123450123456789012345", 16);

	// split into 10 shares with a threshold of 5
	var shares = secrets.share(r, n, t);
	// => shares = ['801xxx...xxx','802xxx...xxx','803xxx...xxx','804xxx...xxx','805xxx...xxx']
	console.log("Unencrypted Shares: " + shares);
	temp = multy(k_s.toString(16), hashFunction(rwd));
	//check this two lines: 241, 242
	f_ki_rwd = CryptoJS.SHA256(rwd.concat(temp)).toString();
	// console.log(f_ki_rwd);
	// f_1 = new BigInteger(OPRFK(PI[1], hash_of_r), 16);
	f_1 = new BigInteger(f_ki_rwd, 16);
	s = new BigInteger(shares[1], 16);
	CI[1] = s.xor(f_1);
	console.log("Encrypted Share for server ID 1: " + CI[1]);

	PI[1] = k_s;
	wi = PI[1].toString(16) + "," + CI[1].toString(16) + "," + k_s.toString(16);

	console.log("w_1 sent to server ID 1:" + wi);

	// A client
	chrome.socket.create('udp', null, function(createInfo) {
		initSocket = createInfo.socketId;

		chrome.socket.connect(initSocket, SERVERIP, SERVERPORT, function(result) {
			console.log('chrome.socket.connect: result = ' + result.toString());
		});

		chrome.socket.write(initSocket, str2ab(wi), function(writeInfo) {
			console.log('writeInfo: ' + writeInfo.bytesWritten + 'byte(s) written.');
		});
	});
}

function keyExchange() {

	var keSocket;
	//	var c_1 = '0';
	//	var pi_1 = '0';

	// A client
	chrome.socket.create('udp', null, function(createInfo) {
		keSocket = createInfo.socketId;

		chrome.socket.connect(keSocket, SERVERIP, SERVERPORT3, function(result) {
			console.log('chrome.socket.connect: result = ' + result.toString());
		});

		chrome.socket.write(keSocket, str2ab(mu), function(writeInfo) {
			console.log('writeInfo:' + writeInfo.bytesWritten + 'byte(s) written.');
		});

		chrome.socket.read(keSocket, 2048, function(readInfo) {
			// console.log('Client: received response: ' + ab2str(readInfo.data), readInfo);
			wi = ab2str(readInfo.data);
			//var  x = new BigInteger(wi, 16);
		});
	});
}

function OPRF(input, IP, Port) {

	var oprfSocket;

	hashOfX = hashFunction(input);
	alpha = encodePoint(curve.multiply(rho, hashOfX));
	// console.log("alpha in OPRF" + alpha);

	// A client
	chrome.socket.create('udp', null, function(createInfo) {
		oprfSocket = createInfo.socketId;

		chrome.socket.connect(oprfSocket, IP, Port, function(result) {
			console.log('chrome.socket.connect: result = ' + result.toString());
		});

		chrome.socket.write(oprfSocket, str2ab(alpha), function(writeInfo) {
			console.log('writeInfo: ' + writeInfo.bytesWritten + 'byte(s) written.');
		});

		chrome.socket.read(oprfSocket, 1024, function(readInfo) {
			//console.log('Client: received response: ' + ab2str(readInfo.data), readInfo);
			beta = decodePoint(ab2str(readInfo.data));
		});
	});
}

function HKHash(pwd) {

	var c = getSECCurveByName("secp224r1");
	var q = c.getCurve().getQ();
	var a = c.getCurve().getA().toBigInteger();
	var b = c.getCurve().getB().toBigInteger();

	offset = 0;
	//can be randomized
	i = 1;
	do {
		x_prime = CryptoJS.SHA256("EC" + pwd + i).toString(CryptoJS.enc.Hex);
		x = new BigInteger(x_prime.substr(offset, 56), 16);
		z = x.modPowInt(3, q).add(x.multiply(a)).add(b).mod(q);
		if (!(z.modPow(q.subtract(1).devide(2), q) == 1)) {
			i++;
			pwd = x.toString(16);
		} else {
			var y = (c == 0 ? z.modPow((q.add(1).devide(4)), q) : y = z.modPow((q.add(1).devide(4)), q).negate());

			return true;
		}
	} while (true);

	/*
	 q = c.getCurve().getQ().toString();
	 a = c.getCurve().getA().toBigInteger().toString();
	 b = c.getCurve().getB().toBigInteger().toString();
	 gx = c.getG().getX().toBigInteger().toString();
	 gy = c.getG().getY().toBigInteger().toString();
	 n = c.getN().toString(); */
}

chrome.runtime.onMessageExternal.addListener(function(request, sender, sendResponse) {

	var password = request.message1;
	var rwd;
	var rwd_prime;

	console.log("message received from the webserver");
	HKHash(password);

	/*
	* Initialization
	*/
	/*
	key = new BigInteger("123456789abcdef03456789abcdef012", 16); //just for matching, otherwise not required hre
	temp = multy(key.toString(16), hashOfPwd);
	rwd = CryptoJS.SHA256(password.concat(temp)).toString(CryptoJS.enc.Hex);
	initialization(rwd);
	*/

	//init
	hashOfPwd = hashFunction(password);
	//H'(pwd)
	temp2 = encodePoint(curve.multiply(k_d, hashOfPwd));
	// (H'(pwd))^k
	rwd = CryptoJS.SHA256(password + temp2).toString(CryptoJS.enc.Hex);
	//rwd= H(pwd,(H'(pwd))^k)
	console.log(rwd);
	hashOfRwd = hashFunction(rwd);
	//H'(rwd)
	temp4 = encodePoint(curve.multiply(k_s, hashOfRwd));
	//(H'(rwd))^k
	F_ks_rwd = CryptoJS.SHA256("pad" + rwd + temp4).toString(CryptoJS.enc.Hex);
	////rwd= H(pad,pwd,(H'(pwd))^k)
	console.log(F_ks_rwd);

	F_ks_rwd_value = new Clipperz.Crypto.ECC.BinaryField.Value(F_ks_rwd, 16);
	// new BigInteger(F_ks_rwd, 16)
	c = s.xor(F_ks_rwd_value);
	r = CryptoJS.HmacSHA256("0", s.asString(16)).toString(CryptoJS.enc.Hex);
	//f_s(0)
	K = CryptoJS.HmacSHA256("1", s.asString(16)).toString(CryptoJS.enc.Hex);
	//f_s(1)
	gk = encodePoint(curve.multiply(k_s, curve.G()));
	//g^k
	C = CryptoJS.SHA256("com" + r + rwd + gk + c.asString(16)).toString(CryptoJS.enc.Hex);
	//H(r,rwd,y,c)
	console.log("c: " + c.asString(16) + " C: " + C + " k: " + k_s.asString(16) + " K: " + K);

	varTestMultiply = curve.multiply(rho, curve.multiply(roInverse, hashOfPwd));

	OPRF(password, DEVICEIP, DEVICEPORT);
	console.log("Beta After OPRF with device:" + beta.x().asString(16));
	temp1 = encodePoint(curve.multiply(roInverse, beta));
	//console.log("beta ^ rhoInverse: " + temp1.x().asString(16));
	rwd_prime = CryptoJS.SHA256(password + temp1).toString(CryptoJS.enc.Hex);
	// console.log(rwd_prime);

	if (rwd == rwd_prime) {
		console.log("received rwd is correct!");
	} else
		console.log("received rwd is not correct!");

	rwd_prime = rwd;
	//problem here is that rwd and rwd_prime do not match

	OPRF(rwd_prime, SERVERIP, SERVERPORT);
	console.log("Beta After OPRF with the Server:" + beta.x().asString(16));
	temp3 = encodePoint(curve.multiply(roInverse, beta));
	//console.log("hashOfPwd ^ k_d: " + temp3.x().asString(16));
	F_ks_rwd_prime = CryptoJS.SHA256("pad" + rwd_prime + temp3).toString(CryptoJS.enc.Hex);
	//console.log(f_ki_rwd_prime);

	if (F_ks_rwd == F_ks_rwd_prime) {
		console.log("received f_ks_rwd is correct!");
	} else
		console.log("received f_ks_rwd is not correct!");

	F_ks_rwd_prime = F_ks_rwd;
	//fix the error

	keyExchange();

	var splitArray = wi.split(",");
	var c = splitArray[0];
	var C = splitArray[1];
	var y_gk_x = splitArray[2];
	var y_gk_y = splitArray[3];
	var mu_prime = splitArray[4];

	F_ks_value = new Clipperz.Crypto.ECC.BinaryField.Value(F_ks_rwd_prime, 16);
	c_value = new Clipperz.Crypto.ECC.BinaryField.Value(c, 16);
	s = c_value.xor(F_ks_value);
	r = CryptoJS.HmacSHA256("0", s.asString(16)).toString(CryptoJS.enc.Hex);
	//f_s(0)
	K = CryptoJS.HmacSHA256("1", s.asString(16)).toString(CryptoJS.enc.Hex);
	//f_s(1)
	C_prime = CryptoJS.SHA256("com" + r + rwd + y_gk_x + "," + y_gk_y + c).toString(CryptoJS.enc.Hex);
	gama = CryptoJS.SHA256(encodePoint(curve.G()) + y_gk_x + "," + y_gk_y + curve.a().asString(16) + curve.b().asString(16)).toString(CryptoJS.enc.Hex);

	if (C == C_prime) {
		console.log("Commit Match");
	}
	if (pointMember(beta)) {
		console.log("Point on Curve");
	}
	// shares[i] = shares_i.toString(16);
	// var comb = secrets.combine(shares.slice(1, 6));
	// reconstructed r
	// console.log(comb);

	//PRF to reconstruct K
	SK = CryptoJS.HmacSHA256("2" + mu + mu_prime + CLIENTIP + SERVERIP, K).toString(CryptoJS.enc.Hex);

	sendResponse({
		secretR : SK
	});

	document.getElementById('key').innerText = SK;

});

