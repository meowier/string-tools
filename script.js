let onOutput = (n)=> {
    document.getElementById('output-area').value = n;
}
let md5 = ()=> {
    onOutput(CryptoJS.MD5(document.getElementById('input-area').value));
}

let sha1 = ()=> {
    onOutput(CryptoJS.SHA1(document.getElementById('input-area').value));
}

let sha256 = ()=> {
    onOutput(CryptoJS.SHA256(document.getElementById('input-area').value));
}

let sha512 = ()=> {
    onOutput(CryptoJS.SHA512(document.getElementById('input-area').value));
}

let sha3512 = ()=> {
    onOutput(CryptoJS.SHA3(document.getElementById('input-area').value, { outputLength: 512 }));
}

let sha3384 = ()=> {
    onOutput(CryptoJS.SHA3(document.getElementById('input-area').value, { outputLength: 384 }));
}

let sha3256 = ()=> {
    onOutput(CryptoJS.SHA3(document.getElementById('input-area').value, { outputLength: 256 }));
}

let sha3224 = ()=> {
    onOutput(CryptoJS.SHA3(document.getElementById('input-area').value, { outputLength: 224 }));
}

let ripemd160 = ()=> {
    onOutput(CryptoJS.RIPEMD160(document.getElementById('input-area').value));
}

let revStr = ()=> {
    onOutput(document.getElementById('input-area').value.split('').reverse().join(''));
}

let lengthStr = ()=> {
    onOutput(document.getElementById('input-area').value.length);
}

let enurl = ()=> {
    onOutput(encodeURIComponent(document.getElementById('input-area').value));
}

let deurl = ()=> {
    onOutput(decodeURIComponent(document.getElementById('input-area').value));
}

let minStr = ()=> {
    let e = document.getElementById('input-area').value;
	let out = e.replace(/ /g, '').split('\n').join('');
	onOutput(out);
}

let buildStr = ()=> {
    let e = document.getElementById('input-area').value.split('\n');
	let out = '';
	for(let i = 0; i < e.length; i++){
		out += i == e.length - 1 ? `' ${e[i]} ';` : `' ${e[i]} ' + \n`;
	}
	onOutput(out);
}

let splitStr = ()=> {
	let e = document.getElementById('input-area').value;
	let k = prompt('Nhập khoảng cách muốn chia:');
	let s = prompt('Nhập kí tự ngăn cách: (mặc định bỏ trống là dấu cách)').toString();
	let re = s === '' ? ' ' : s;
	let pattern = new RegExp(`[a-zA-Z0-9:\/!@#$%^&*()?'"_.,<>\\[\\]\\-=+]{${k}}`, 'gm');
	let out = e.match(pattern);
	onOutput(out.join(re) + re + e.slice(out.join('').length, e.length));
}

let rot13 = ()=> {
	function rot(s, i) {
		return s.replace(/[a-zA-Z]/g, function (c) {
			return String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + i) ? c : c - 26);
		});
    }
    onOutput(rot(document.getElementById('input-area').value, 13));
}

let upper = ()=> {
    onOutput(document.getElementById('input-area').value.toUpperCase());
}

let lower = ()=> {
    onOutput(document.getElementById('input-area').value.toLowerCase());
}
!function(t,n){var r,e;"object"==typeof exports&&"undefined"!=typeof module?module.exports=n():"function"==typeof define&&define.amd?define(n):(r=t.Base64,(e=n()).noConflict=function(){return t.Base64=r,e},t.Meteor&&(Base64=e),t.Base64=e)}("undefined"!=typeof self?self:"undefined"!=typeof window?window:"undefined"!=typeof global?global:this,(function(){"use strict";var t,n="3.7.5",r="function"==typeof atob,e="function"==typeof btoa,o="function"==typeof Buffer,u="function"==typeof TextDecoder?new TextDecoder:void 0,i="function"==typeof TextEncoder?new TextEncoder:void 0,f=Array.prototype.slice.call("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="),c=(t={},f.forEach((function(n,r){return t[n]=r})),t),a=/^(?:[A-Za-z\d+\/]{4})*?(?:[A-Za-z\d+\/]{2}(?:==)?|[A-Za-z\d+\/]{3}=?)?$/,d=String.fromCharCode.bind(String),s="function"==typeof Uint8Array.from?Uint8Array.from.bind(Uint8Array):function(t){return new Uint8Array(Array.prototype.slice.call(t,0))},l=function(t){return t.replace(/=/g,"").replace(/[+\/]/g,(function(t){return"+"==t?"-":"_"}))},h=function(t){return t.replace(/[^A-Za-z0-9\+\/]/g,"")},p=function(t){for(var n,r,e,o,u="",i=t.length%3,c=0;c<t.length;){if((r=t.charCodeAt(c++))>255||(e=t.charCodeAt(c++))>255||(o=t.charCodeAt(c++))>255)throw new TypeError("invalid character found");u+=f[(n=r<<16|e<<8|o)>>18&63]+f[n>>12&63]+f[n>>6&63]+f[63&n]}return i?u.slice(0,i-3)+"===".substring(i):u},y=e?function(t){return btoa(t)}:o?function(t){return Buffer.from(t,"binary").toString("base64")}:p,A=o?function(t){return Buffer.from(t).toString("base64")}:function(t){for(var n=[],r=0,e=t.length;r<e;r+=4096)n.push(d.apply(null,t.subarray(r,r+4096)));return y(n.join(""))},b=function(t,n){return void 0===n&&(n=!1),n?l(A(t)):A(t)},g=function(t){if(t.length<2)return(n=t.charCodeAt(0))<128?t:n<2048?d(192|n>>>6)+d(128|63&n):d(224|n>>>12&15)+d(128|n>>>6&63)+d(128|63&n);var n=65536+1024*(t.charCodeAt(0)-55296)+(t.charCodeAt(1)-56320);return d(240|n>>>18&7)+d(128|n>>>12&63)+d(128|n>>>6&63)+d(128|63&n)},B=/[\uD800-\uDBFF][\uDC00-\uDFFFF]|[^\x00-\x7F]/g,x=function(t){return t.replace(B,g)},C=o?function(t){return Buffer.from(t,"utf8").toString("base64")}:i?function(t){return A(i.encode(t))}:function(t){return y(x(t))},m=function(t,n){return void 0===n&&(n=!1),n?l(C(t)):C(t)},v=function(t){return m(t,!0)},U=/[\xC0-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF7][\x80-\xBF]{3}/g,F=function(t){switch(t.length){case 4:var n=((7&t.charCodeAt(0))<<18|(63&t.charCodeAt(1))<<12|(63&t.charCodeAt(2))<<6|63&t.charCodeAt(3))-65536;return d(55296+(n>>>10))+d(56320+(1023&n));case 3:return d((15&t.charCodeAt(0))<<12|(63&t.charCodeAt(1))<<6|63&t.charCodeAt(2));default:return d((31&t.charCodeAt(0))<<6|63&t.charCodeAt(1))}},w=function(t){return t.replace(U,F)},S=function(t){if(t=t.replace(/\s+/g,""),!a.test(t))throw new TypeError("malformed base64.");t+="==".slice(2-(3&t.length));for(var n,r,e,o="",u=0;u<t.length;)n=c[t.charAt(u++)]<<18|c[t.charAt(u++)]<<12|(r=c[t.charAt(u++)])<<6|(e=c[t.charAt(u++)]),o+=64===r?d(n>>16&255):64===e?d(n>>16&255,n>>8&255):d(n>>16&255,n>>8&255,255&n);return o},E=r?function(t){return atob(h(t))}:o?function(t){return Buffer.from(t,"base64").toString("binary")}:S,D=o?function(t){return s(Buffer.from(t,"base64"))}:function(t){return s(E(t).split("").map((function(t){return t.charCodeAt(0)})))},R=function(t){return D(T(t))},z=o?function(t){return Buffer.from(t,"base64").toString("utf8")}:u?function(t){return u.decode(D(t))}:function(t){return w(E(t))},T=function(t){return h(t.replace(/[-_]/g,(function(t){return"-"==t?"+":"/"})))},Z=function(t){return z(T(t))},j=function(t){return{value:t,enumerable:!1,writable:!0,configurable:!0}},I=function(){var t=function(t,n){return Object.defineProperty(String.prototype,t,j(n))};t("fromBase64",(function(){return Z(this)})),t("toBase64",(function(t){return m(this,t)})),t("toBase64URI",(function(){return m(this,!0)})),t("toBase64URL",(function(){return m(this,!0)})),t("toUint8Array",(function(){return R(this)}))},O=function(){var t=function(t,n){return Object.defineProperty(Uint8Array.prototype,t,j(n))};t("toBase64",(function(t){return b(this,t)})),t("toBase64URI",(function(){return b(this,!0)})),t("toBase64URL",(function(){return b(this,!0)}))},P={version:n,VERSION:"3.7.5",atob:E,atobPolyfill:S,btoa:y,btoaPolyfill:p,fromBase64:Z,toBase64:m,encode:m,encodeURI:v,encodeURL:v,utob:x,btou:w,decode:Z,isValid:function(t){if("string"!=typeof t)return!1;var n=t.replace(/\s+/g,"").replace(/={0,2}$/,"");return!/[^\s0-9a-zA-Z\+/]/.test(n)||!/[^\s0-9a-zA-Z\-_]/.test(n)},fromUint8Array:b,toUint8Array:R,extendString:I,extendUint8Array:O,extendBuiltins:function(){I(),O()},Base64:{}};return Object.keys(P).forEach((function(t){return P.Base64[t]=P[t]})),P}));
let enbase64 = ()=> {
    onOutput(window.Base64.encode(document.getElementById('input-area').value));
}

let debase64 = ()=> {
    onOutput(window.Base64.decode(document.getElementById('input-area').value));
}

let remRep = ()=> {
	let find = prompt('Nhập kí tự bạn muốn tìm:');
	let rep = prompt('Nhập kí tự muốn thay thế, nếu muốn xoá thì bỏ trống:');
	if (rep == "\\n") {
		rep = "\n";
	}
	else if (rep == "\\t") {
		rep = "\t";
	}
	onOutput(document.getElementById('input-area').value.split(find).join(rep));
}

let debase32 = ()=> {
    onOutput(base32_decode(document.getElementById('input-area').value));
}

let enbase32 = ()=> {
    onOutput(base32_encode(document.getElementById('input-area').value));
}

let escapseJs = () => {
    let e = document.getElementById('input-area').value;
    let out = '';
	if (e[0] == "/" && e[e.length - 1] == "/") {
		let esc = [".", "\\", "+", "*", "?", "[", "]", "^", "$", "(", ")", "{", "}", "=", "!", "<", ">", "|", ":", "-"]
		out = e.split('').map((v, i) => {
			if (i == 0 || i == e.length - 1) return v
			if (esc.includes(v) && e[i-1] !== "\\") return "\\" + v
			else return v
		}).join('')
	} else {
		try {
			if(typeof JSON.parse(e) === 'object') {
				out = JSON.stringify(e);	
			} else {
				out = e	
			}
		} catch (err) {
			out = e.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t").replace(/\f/g, "\\f").replace(/[\b]/g, "\\b");
		}
	}
    onOutput(out);
}

let unescapseJs = () => {
    let e = document.getElementById('input-area').value;
	let map = { 'n': '\n', 'r': '\r', 't': '\t', 'b': '\b', 'f': '\f', '"': '"', "'": "'", '&': '&', '\\': '\\', '/': '/' };
	let out = '';
	for (let i = 0; i < e.length; i++) {
		if (e[i] === '\\' && i + 1 < e.length) {
			let nx = e[i + 1];
			if (nx === 'u' && /^[0-9a-fA-F]{4}$/.test(e.substr(i + 2, 4))) {
				out += String.fromCharCode(parseInt(e.substr(i + 2, 4), 16));
				i += 5;
			} else if (map[nx] !== undefined) {
				out += map[nx];
				i += 1;
			} else {
				out += nx;
				i += 1;
			}
		} else {
			out += e[i];
		}
	}
    onOutput(out);
}

let strToHex = ()=> {
	let e = document.getElementById('input-area').value;
	let out = Array.from(new TextEncoder().encode(e))
		.map(b => b.toString(16).padStart(2, '0'))
		.join('');
	onOutput(out);
}

let hexToStr = ()=> {
	let e  = document.getElementById('input-area').value.replace(/\s+/g, '');
	let bytes = [];
	for (let n = 0; n < e.length; n += 2) {
		bytes.push(parseInt(e.substr(n, 2), 16));
	}
	onOutput(new TextDecoder().decode(new Uint8Array(bytes)));
}

let strToBin = ()=> {
	onOutput(Array
		.from(document.getElementById('input-area').value)
		.reduce((acc, char) => acc.concat(char.charCodeAt().toString(2)), [])
		.map(bin => '0'.repeat(8 - bin.length) + bin )
		.join(' '));
}

let binToStr = ()=> {
	onOutput(document.getElementById('input-area').value.split(/\s/).map(function (val){
		return String.fromCharCode(parseInt(val, 2));
	  }).join(""));
}

let strToDec = ()=> {
	let e = document.getElementById('input-area').value;
	let bytes = [];
	for (let i = 0; i < e.length; i++) {
		let realBytes = unescape(encodeURIComponent(e[i]));
		for (let j = 0; j < realBytes.length; j++) {
			bytes.push(realBytes[j].charCodeAt(0));
		}
	}
	let converted = [];
	for (let i = 0; i < bytes.length; i++) {
		let byte = bytes[i].toString(10);
		converted.push(byte);
	}

	onOutput(converted.join(' '));
}

let decToStr = ()=> {
	let e = document.getElementById('input-area').value;
	e = e.replace(/\s+/g, ' ');
	bytes = e.split(' ');
	let out = '';
	for (let i = 0; i < bytes.length; i++) {
		out += String.fromCharCode(bytes[i]);
	}
	onOutput(out);
}

let strToMorse = ()=> {
	let alphabet = {
		'a':  '.-',
		'b':  '-...',
		'c':  '-.-.',
		'd':  '-..',
		'e':  '.',
		'f':  '..-.',
		'g':  '--.',
		'h':  '....',
		'i':  '..',
		'j':  '.---',
		'k':  '-.-',
		'l':  '.-..',
		'm':  '--',
		'n':  '-.',
		'o':  '---',
		'p':  '.--.',
		'q':  '--.-',
		'r':  '.-.',
		's':  '...',
		't':  '-',
		'u':  '..-',
		'v':  '...-',
		'w':  '.--',
		'x':  '-..-',
		'y':  '-.--',
		'z':  '--..',
		'á':  '.--.-',
		'ä':  '.-.-',
		'é':  '..-..',
		'ñ':  '--.--',
		'ö':  '---.',
		'ü':  '..--',
		'1':  '.----',
		'2':  '..---',
		'3':  '...--',
		'4':  '....-',
		'5':  '.....',
		'6':  '-....',
		'7':  '--...',
		'8':  '---..',
		'9':  '----.',
		'0':  '-----',
		',':  '--..--',
		'.':  '.-.-.-',
		'?':  '..--..',
		';':  '-.-.-',
		':':  '---...',
		'/':  '-..-.',
		'-':  '-....-',
		'\'': '.----.',
		'()': '-.--.-',
		'_':  '..--.-',
		'@':  '.--.-.',
		' ':  '.......'
	  };
	onOutput(document.getElementById('input-area').value
		.split('')            
		.map(function(e){     
			return alphabet[e.toLowerCase()] || '';
		})
		.join(' ')            
		.replace(/ +/g, ' '));
}

let mourseToStr = ()=> {
	let e = document.getElementById('input-area').value;
	let alphabet = {
		'.-':     'a',
		'-...':   'b',
		'-.-.':   'c',
		'-..':    'd',
		'.':      'e',
		'..-.':   'f',
		'--.':    'g',
		'....':   'h',
		'..':     'i',
		'.---':   'j',
		'-.-':    'k',
		'.-..':   'l',
		'--':     'm',
		'-.':     'n',
		'---':    'o',
		'.--.':   'p',
		'--.-':   'q',
		'.-.':    'r',
		'...':    's',
		'-':      't',
		'..-':    'u',
		'...-':   'v',
		'.--':    'w',
		'-..-':   'x',
		'-.--':   'y',
		'--..':   'z',
		'.--.-':  'á',
		'.-.-':   'ä',
		'..-..':  'é',
		'--.--':  'ñ',
		'---.':   'ö',
		'..--':   'ü',
		'.----':  '1',
		'..---':  '2',
		'...--':  '3',
		'....-':  '4',
		'.....':  '5',
		'-....':  '6',
		'--...':  '7',
		'---..':  '8',
		'----.':  '9',
		'-----':  '0',
		'--..--': ',',
		'.-.-.-': '.',
		'..--..': '?',
		'-.-.-':  ';',
		'---...': ':',
		'-..-.':  '/',
		'-....-': '-',
		'.----.': '\'',
		'-.--.-': '()',
		'..--.-': '_',
		'.--.-.': '@'
	};
	let words = e.split(/\s{3,}|\.{6,7}/);
    for (let i = 0; i < words.length; i++) {
        let word = words[i];
        word = word.replace(/^\s+/, '');
        word = word.replace(/\s+$/, '');
        word = word.replace(/\s+/, ' ');
        words[i] = word;
    }
    var ret = '';
    for (let i = 0; i < words.length; i++) {
        let word = words[i];
        let chars = word.split(' ');
        for (let j = 0; j < chars.length; j++) {
            let char = chars[j];
            if (alphabet[char]) {
                var letter = alphabet[char];
            }
            else {
                var letter = '?'
            }
            ret += letter;
        }
        ret += ' ';
    }
    onOutput(ret);
}

let md4hash = ()=> {
	onOutput(md4(document.getElementById('input-area').value));
}

let md2hash = ()=> {
	onOutput(md2(document.getElementById('input-area').value));
}

let dehtml = ()=> {
	onOutput(htmlDecode(document.getElementById('input-area').value));
}

let enhtml = ()=> {
	onOutput(htmlEncode(document.getElementById('input-area').value));
}

let hex2sid = ()=> {
	let hexs = document.getElementById('input-area').value;
	hexs = hexs
	  .split("")
	  .filter(c => "0123456789abcdef".includes(c.toLowerCase()))
	  .join("");
	
	function hexToBytes(hex) {
	  if (hex.length % 2 !== 0) throw new Error("Invalid hex length");
	  const out = new Uint8Array(hex.length / 2);
	  for (let i = 0; i < out.length; i++) {
	    out[i] = parseInt(hex.substr(i * 2, 2), 16);
	  }
	  return out;
	}
	
	const b = hexToBytes(hexs);
	
	const rev = b[0];
	const subc = b[1];
	
	// Identifier Authority (6 bytes, big-endian) -> BigInt
	let ident = 0n;
	for (let i = 2; i < 8; i++) {
	  ident = (ident << 8n) | BigInt(b[i]);
	}
	
	// SubAuthorities (4 bytes each, little-endian) -> unsigned 32-bit number
	const subs = [];
	for (let i = 0; i < subc; i++) {
	  const off = 8 + 4 * i;
	  const val =
	    (b[off]) |
	    (b[off + 1] << 8) |
	    (b[off + 2] << 16) |
	    (b[off + 3] << 24);
	  subs.push(val >>> 0);
	}
	
	onOutput(`S-${rev}-${ident.toString()}` + subs.map(s => `-${s}`).join(""));
}

/* ===================== Tính năng bổ sung ===================== */

// String <-> Octal (theo byte UTF-8, mỗi byte 3 chữ số bát phân)
let strToOct = ()=> {
	let e = document.getElementById('input-area').value;
	onOutput(Array.from(new TextEncoder().encode(e)).map(b => b.toString(8).padStart(3, '0')).join(' '));
}

let octToStr = ()=> {
	let bytes = document.getElementById('input-area').value.trim().split(/\s+/).filter(x => x.length).map(o => parseInt(o, 8));
	onOutput(new TextDecoder().decode(new Uint8Array(bytes)));
}

// Universal base: nhận thập phân hoặc tiền tố 0x / 0b / 0o, in ra cả 4 hệ
let allBases = ()=> {
	let s = document.getElementById('input-area').value.trim();
	let v;
	try { v = BigInt(s); } catch (err) { onOutput('Số không hợp lệ. Dùng số thập phân hoặc tiền tố 0x / 0b / 0o.'); return; }
	let neg = v < 0n, a = neg ? -v : v, sign = neg ? '-' : '';
	onOutput(['BIN: ' + sign + a.toString(2), 'OCT: ' + sign + a.toString(8), 'DEC: ' + sign + a.toString(10), 'HEX: ' + sign + a.toString(16)].join('\n'));
}

// Chuyển giữa hai hệ cơ số bất kỳ (2-36)
let anyBase = ()=> {
	let s = document.getElementById('input-area').value.trim();
	let from = parseInt(prompt('Hệ cơ số nguồn (2-36):'), 10);
	let to = parseInt(prompt('Hệ cơ số đích (2-36):'), 10);
	if (!(from >= 2 && from <= 36 && to >= 2 && to <= 36)) { onOutput('Cơ số phải trong khoảng 2-36.'); return; }
	let n = parseInt(s, from);
	if (Number.isNaN(n)) { onOutput('Input không hợp lệ ở cơ số ' + from + '.'); return; }
	onOutput(n.toString(to));
}

// String <-> Unicode code point (U+XXXX), xử lý đúng emoji/surrogate pair
let strToCodepoint = ()=> {
	let e = document.getElementById('input-area').value;
	onOutput(Array.from(e).map(ch => 'U+' + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')).join(' '));
}

let codepointToStr = ()=> {
	let e = document.getElementById('input-area').value.trim();
	onOutput(e.split(/\s+/).filter(x => x.length).map(t => String.fromCodePoint(parseInt(t.replace(/^U\+/i, ''), 16))).join(''));
}

// XOR cipher với key lặp lại; mã hoá ra hex, giải mã từ hex
let xorStr = ()=> {
	let e = new TextEncoder().encode(document.getElementById('input-area').value);
	let key = prompt('Nhập key XOR:');
	if (!key) { onOutput('Cần nhập key.'); return; }
	let k = new TextEncoder().encode(key);
	onOutput(Array.from(e).map((b, i) => (b ^ k[i % k.length]).toString(16).padStart(2, '0')).join(''));
}

let unxorHex = ()=> {
	let hex = document.getElementById('input-area').value.replace(/\s+/g, '');
	let key = prompt('Nhập key XOR:');
	if (!key) { onOutput('Cần nhập key.'); return; }
	let k = new TextEncoder().encode(key);
	let bytes = [];
	for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
	onOutput(new TextDecoder().decode(new Uint8Array(bytes.map((b, i) => b ^ k[i % k.length]))));
}

// Hex dump kiểu xxd: offset + 16 byte hex + cột ASCII
let hexDump = ()=> {
	let bytes = new TextEncoder().encode(document.getElementById('input-area').value);
	let lines = [];
	for (let off = 0; off < bytes.length; off += 16) {
		let chunk = bytes.slice(off, off + 16);
		let hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0'));
		let hexStr = (hex.slice(0, 8).join(' ') + '  ' + hex.slice(8).join(' ')).padEnd(48, ' ');
		let ascii = Array.from(chunk).map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
		lines.push(off.toString(16).padStart(8, '0') + '  ' + hexStr + ' |' + ascii + '|');
	}
	onOutput(lines.join('\n') || '(empty)');
}

// Giải mã JWT: tách header.payload.signature, decode base64url + pretty-print JSON
let jwtDecode = ()=> {
	let parts = document.getElementById('input-area').value.trim().split('.');
	if (parts.length < 2) { onOutput('Không phải JWT hợp lệ (cần dạng header.payload.signature).'); return; }
	let dec = (seg) => { try { return JSON.stringify(JSON.parse(window.Base64.decode(seg)), null, 2); } catch (err) { return '(không giải mã được) ' + seg; } };
	onOutput('=== HEADER ===\n' + dec(parts[0]) + '\n\n=== PAYLOAD ===\n' + dec(parts[1]) + '\n\n=== SIGNATURE ===\n' + (parts[2] || '(none)'));
}

// Bỏ dấu tiếng Việt
let removeDiacritics = ()=> {
	let e = document.getElementById('input-area').value;
	onOutput(e.normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/đ/g, 'd').replace(/Đ/g, 'D'));
}

let encryptButton = document.getElementById('encrypt');
let decryptButton = document.getElementById('decrypt');

let onEncrypt = ()=> {
	let p = document.getElementById('phrase').value;
	console.log('Button Clicked!');
	let e = document.getElementById("hash");
	let valueEncrypt = e.options[e.selectedIndex].value;
	switch(valueEncrypt) {
		case 'hmacmd5':
			onOutput(CryptoJS.HmacMD5(document.getElementById('input-area').value, p));
			break;
		case 'hmacsha1':
			onOutput(CryptoJS.HmacSHA1(document.getElementById('input-area').value, p));
			break;
		case 'hmacsha256':
			onOutput(CryptoJS.HmacSHA256(document.getElementById('input-area').value, p));
			break;
		case 'hmacsha512':
			onOutput(CryptoJS.HmacSHA512(document.getElementById('input-area').value, p));
			break;
		case 'aes':
			onOutput(CryptoJS.AES.encrypt(document.getElementById('input-area').value, p));
			break;
		case 'des':
			onOutput(CryptoJS.DES.encrypt(document.getElementById('input-area').value, p));
			break;
		case 'tripledes':
			onOutput(CryptoJS.TripleDES.encrypt(document.getElementById('input-area').value, p));
			break;
		case 'rc4':
			onOutput(CryptoJS.RC4.encrypt(document.getElementById('input-area').value, p));
			break;
		case 'rc4drop':
			onOutput(CryptoJS.RC4Drop.encrypt(document.getElementById('input-area').value, p));
			break;
		default:
			onOutput('Encrypt Invalid!');

	}
}

let onDecrypt = ()=> {
	let p = document.getElementById('phrase').value;
	console.log('Button Clicked!');
	let e = document.getElementById("hash");
	let valueEncrypt = e.options[e.selectedIndex].value;
	switch(valueEncrypt) {
		case 'aes':			
			onOutput(CryptoJS.AES.decrypt(document.getElementById('input-area').value, p).toString(CryptoJS.enc.Utf8));
			break;
		case 'des':
			onOutput(CryptoJS.DES.decrypt(document.getElementById('input-area').value, p).toString(CryptoJS.enc.Utf8));
			break;
		case 'tripledes':
			onOutput(CryptoJS.TripleDES.decrypt(document.getElementById('input-area').value, p).toString(CryptoJS.enc.Utf8));
			break;
		case 'rc4':
			onOutput(CryptoJS.RC4.decrypt(document.getElementById('input-area').value, p).toString(CryptoJS.enc.Utf8));
			break;
		case 'rc4drop':
			onOutput(CryptoJS.RC4Drop.decrypt(document.getElementById('input-area').value, p).toString(CryptoJS.enc.Utf8));
			break;
		default:
			onOutput('Decrypt Invalid!');

	}

}
encryptButton.addEventListener('click', onEncrypt);
decryptButton.addEventListener('click', onDecrypt);


/* ===================== CTF Toolkit (bổ sung) ===================== */

// ROT47: xoay toàn bộ ASCII in được (33-126), bù cho ROT13. Tự nghịch đảo.
let rot47 = ()=> {
	let e = document.getElementById('input-area').value;
	onOutput(e.replace(/[\x21-\x7e]/g, c => String.fromCharCode(33 + (c.charCodeAt(0) - 33 + 47) % 94)));
}

// Caesar/ROTn: dịch chữ cái với shift bất kỳ. Nhập n; in luôn cả 25 dịch chuyển để brute-force.
let caesar = ()=> {
	let e = document.getElementById('input-area').value;
	let inp = prompt('Nhập shift (số), để trống = in tất cả 25 khả năng để brute-force:');
	let shift = (c, i) => c.replace(/[a-zA-Z]/g, ch => {
		let base = ch <= 'Z' ? 65 : 97;
		return String.fromCharCode((ch.charCodeAt(0) - base + (i % 26 + 26) % 26) % 26 + base);
	});
	if (inp === null) return;
	if (inp.trim() === '') {
		let lines = [];
		for (let i = 1; i <= 25; i++) lines.push('ROT' + String(i).padStart(2, '0') + ': ' + shift(e, i));
		onOutput(lines.join('\n'));
	} else {
		onOutput(shift(e, parseInt(inp, 10) || 0));
	}
}

// Atbash: gương bảng chữ cái (a<->z). Tự nghịch đảo.
let atbash = ()=> {
	let e = document.getElementById('input-area').value;
	onOutput(e.replace(/[a-zA-Z]/g, c => {
		let base = c <= 'Z' ? 65 : 97;
		return String.fromCharCode(base + 25 - (c.charCodeAt(0) - base));
	}));
}

// Vigenère mã hoá: nhập key, chỉ dịch chữ cái, giữ nguyên ký tự khác và hoa/thường.
let vigenereEnc = ()=> {
	let e = document.getElementById('input-area').value;
	let key = (prompt('Nhập key Vigenère (chỉ chữ cái):') || '').replace(/[^a-zA-Z]/g, '').toLowerCase();
	if (!key) { onOutput('Cần nhập key gồm chữ cái.'); return; }
	let j = 0, out = '';
	for (let ch of e) {
		if (/[a-zA-Z]/.test(ch)) {
			let base = ch <= 'Z' ? 65 : 97;
			let k = key.charCodeAt(j % key.length) - 97;
			out += String.fromCharCode((ch.charCodeAt(0) - base + k) % 26 + base);
			j++;
		} else out += ch;
	}
	onOutput(out);
}

// Vigenère giải mã.
let vigenereDec = ()=> {
	let e = document.getElementById('input-area').value;
	let key = (prompt('Nhập key Vigenère (chỉ chữ cái):') || '').replace(/[^a-zA-Z]/g, '').toLowerCase();
	if (!key) { onOutput('Cần nhập key gồm chữ cái.'); return; }
	let j = 0, out = '';
	for (let ch of e) {
		if (/[a-zA-Z]/.test(ch)) {
			let base = ch <= 'Z' ? 65 : 97;
			let k = key.charCodeAt(j % key.length) - 97;
			out += String.fromCharCode((ch.charCodeAt(0) - base - k + 26) % 26 + base);
			j++;
		} else out += ch;
	}
	onOutput(out);
}

// A1Z26 mã hoá: chữ -> số (a=1..z=26), cách nhau bởi '-', từ cách nhau bởi ' '.
let a1z26Enc = ()=> {
	let e = document.getElementById('input-area').value.toLowerCase();
	onOutput(e.split(/\s+/).map(w =>
		w.split('').map(c => (c >= 'a' && c <= 'z') ? (c.charCodeAt(0) - 96) : c).join('-')
	).join(' '));
}

// A1Z26 giải mã: nhận số ngăn cách bởi ký tự không phải số.
let a1z26Dec = ()=> {
	let e = document.getElementById('input-area').value.trim();
	onOutput(e.split(/\s+/).map(w =>
		w.split(/[^0-9]+/).filter(x => x.length).map(n => {
			let v = parseInt(n, 10);
			return (v >= 1 && v <= 26) ? String.fromCharCode(96 + v) : '?';
		}).join('')
	).join(' '));
}

// Bacon cipher mã hoá (biến thể 26 chữ riêng biệt, 5 bit A/B).
let baconEnc = ()=> {
	let e = document.getElementById('input-area').value.toUpperCase();
	onOutput(e.replace(/[A-Z]/g, c =>
		(c.charCodeAt(0) - 65).toString(2).padStart(5, '0').replace(/0/g, 'A').replace(/1/g, 'B')
	));
}

// Bacon cipher giải mã: gom A/B (hoặc 0/1) thành nhóm 5 bit.
let baconDec = ()=> {
	let bits = document.getElementById('input-area').value.toUpperCase().replace(/[^AB01]/g, '').replace(/0/g, 'A').replace(/1/g, 'B');
	let out = '';
	for (let i = 0; i + 5 <= bits.length; i += 5) {
		let v = parseInt(bits.substr(i, 5).replace(/A/g, '0').replace(/B/g, '1'), 2);
		out += (v >= 0 && v <= 25) ? String.fromCharCode(65 + v) : '?';
	}
	onOutput(out);
}

// NTLM hash = MD4(UTF-16LE(password)). Rất hay dùng khi crack Windows.
let ntlm = ()=> {
	let s = document.getElementById('input-area').value;
	let bytes = [];
	for (let i = 0; i < s.length; i++) {
		let c = s.charCodeAt(i);
		bytes.push(c & 0xff, (c >> 8) & 0xff);
	}
	onOutput(md4(bytes).toUpperCase());
}

// CRC32 checksum (chuẩn IEEE, in hex 8 ký tự).
let crc32 = ()=> {
	let bytes = new TextEncoder().encode(document.getElementById('input-area').value);
	let table = crc32.table || (crc32.table = (() => {
		let t = [];
		for (let n = 0; n < 256; n++) {
			let c = n;
			for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
			t[n] = c >>> 0;
		}
		return t;
	})());
	let crc = 0xFFFFFFFF;
	for (let i = 0; i < bytes.length; i++) crc = (crc >>> 8) ^ table[(crc ^ bytes[i]) & 0xFF];
	onOutput(((crc ^ 0xFFFFFFFF) >>> 0).toString(16).padStart(8, '0'));
}

// Base58 (bảng Bitcoin) mã hoá từ chuỗi UTF-8.
let enbase58 = ()=> {
	let A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
	let bytes = Array.from(new TextEncoder().encode(document.getElementById('input-area').value));
	if (!bytes.length) { onOutput(''); return; }
	let zeros = 0; while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
	let digits = [0];
	for (let i = zeros; i < bytes.length; i++) {
		let carry = bytes[i];
		for (let j = 0; j < digits.length; j++) { carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0; }
		while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
	}
	let out = '1'.repeat(zeros) + digits.reverse().map(d => A[d]).join('');
	onOutput(out);
}

// Base58 giải mã -> chuỗi UTF-8.
let debase58 = ()=> {
	let A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
	let s = document.getElementById('input-area').value.trim();
	if (!s) { onOutput(''); return; }
	let bytes = [0];
	for (let ch of s) {
		let val = A.indexOf(ch);
		if (val < 0) { onOutput('Ký tự không hợp lệ trong Base58: ' + ch); return; }
		let carry = val;
		for (let j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>= 8; }
		while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
	}
	let zeros = 0; while (zeros < s.length && s[zeros] === '1') zeros++;
	bytes.reverse();
	let arr = new Uint8Array(zeros + (bytes.length - (bytes[0] === 0 ? 1 : 0)));
	// loại byte 0 thừa ở đầu
	while (bytes.length > 1 && bytes[0] === 0) bytes.shift();
	let full = new Uint8Array(zeros + bytes.length);
	full.set(bytes, zeros);
	onOutput(new TextDecoder().decode(full));
}

// Shannon entropy: bit/ký tự + tổng bit, gợi ý mức ngẫu nhiên.
let entropy = ()=> {
	let e = document.getElementById('input-area').value;
	if (!e.length) { onOutput('(empty)'); return; }
	let freq = {};
	for (let ch of e) freq[ch] = (freq[ch] || 0) + 1;
	let H = 0, n = e.length;
	for (let k in freq) { let p = freq[k] / n; H -= p * Math.log2(p); }
	let hint = H < 3 ? 'thấp (văn bản/lặp lại)' : H < 4.5 ? 'trung bình (text tự nhiên)' : 'cao (nén/mã hoá/ngẫu nhiên)';
	onOutput([
		'Shannon entropy: ' + H.toFixed(4) + ' bit/ký tự',
		'Tổng: ' + (H * n).toFixed(2) + ' bit (~' + Math.ceil(H * n / 8) + ' byte)',
		'Số ký tự: ' + n + ', ký tự khác nhau: ' + Object.keys(freq).length,
		'Đánh giá: ' + hint
	].join('\n'));
}

// Frequency analysis + Index of Coincidence (đoán cipher dịch chuyển vs thay thế).
let freqAnalysis = ()=> {
	let e = document.getElementById('input-area').value;
	if (!e.length) { onOutput('(empty)'); return; }
	let freq = {};
	for (let ch of e) freq[ch] = (freq[ch] || 0) + 1;
	let sorted = Object.entries(freq).sort((a, b) => b[1] - a[1]);
	let disp = c => c === ' ' ? '␠(space)' : c === '\n' ? '␤(\\n)' : c === '\t' ? '␉(\\t)' : c;
	let lines = sorted.map(([c, n]) => disp(c).padEnd(10) + n + '  (' + (100 * n / e.length).toFixed(2) + '%)');
	// Index of Coincidence trên chữ cái A-Z
	let letters = e.toUpperCase().replace(/[^A-Z]/g, '');
	let lf = {}; for (let c of letters) lf[c] = (lf[c] || 0) + 1;
	let N = letters.length, ic = 0;
	for (let k in lf) ic += lf[k] * (lf[k] - 1);
	ic = N > 1 ? ic / (N * (N - 1)) : 0;
	let icHint = ic > 0.06 ? 'gần tiếng Anh ~0.067 -> có thể là mã thay thế đơn/Caesar' :
	             ic > 0.045 ? 'trung gian -> có thể Vigenère key ngắn' :
	             'thấp ~0.038 -> Vigenère key dài / ngẫu nhiên';
	onOutput('=== Tần suất ký tự ===\n' + lines.join('\n') +
		'\n\n=== Index of Coincidence (A-Z) ===\nIC = ' + ic.toFixed(4) + '\n' + icHint);
}

// Hash identifier: đoán loại hash từ độ dài & charset (gợi ý, không chắc chắn 100%).
let hashId = ()=> {
	let h = document.getElementById('input-area').value.trim();
	let guesses = [];
	if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(h)) guesses.push('bcrypt');
	if (/^\$1\$/.test(h)) guesses.push('md5crypt ($1$)');
	if (/^\$5\$/.test(h)) guesses.push('sha256crypt ($5$)');
	if (/^\$6\$/.test(h)) guesses.push('sha512crypt ($6$)');
	if (/^\$apr1\$/.test(h)) guesses.push('Apache apr1-md5');
	if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(h) && h.split('.').length === 3) guesses.push('JWT (dùng nút JWT Decode)');
	let hex = /^[a-fA-F0-9]+$/.test(h);
	if (hex) {
		let map = {
			16: ['CRC-64? / MySQL323'],
			8:  ['CRC-32 / Adler-32'],
			32: ['MD5', 'MD4', 'NTLM', 'MD2', 'RIPEMD-128', 'LM'],
			40: ['SHA-1', 'RIPEMD-160', 'HAVAL-160'],
			56: ['SHA-224', 'SHA3-224'],
			64: ['SHA-256', 'SHA3-256', 'Keccak-256', 'RIPEMD-256', 'BLAKE2s'],
			96: ['SHA-384', 'SHA3-384'],
			128:['SHA-512', 'SHA3-512', 'Whirlpool', 'BLAKE2b']
		};
		if (map[h.length]) guesses.push('hex ' + h.length + ' ký tự -> ' + map[h.length].join(', '));
		else guesses.push('hex ' + h.length + ' ký tự (không khớp độ dài phổ biến)');
	}
	if (/^[A-Za-z0-9+/]+={0,2}$/.test(h) && h.length % 4 === 0) guesses.push('có thể là Base64 (thử nút Decode base64)');
	onOutput(guesses.length ? '=== Hash có thể là ===\n- ' + guesses.join('\n- ') : 'Không nhận diện được. Kiểm tra lại độ dài/charset.');
}
