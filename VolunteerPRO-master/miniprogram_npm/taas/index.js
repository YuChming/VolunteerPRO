module.exports = (function() {
var __MODS__ = {};
var __DEFINE__ = function(modId, func, req) { var m = { exports: {} }; __MODS__[modId] = { status: 0, func: func, req: req, m: m }; };
var __REQUIRE__ = function(modId, source) { if(!__MODS__[modId]) return require(source); if(!__MODS__[modId].status) { var m = { exports: {} }; __MODS__[modId].status = 1; __MODS__[modId].func(__MODS__[modId].req, m, m.exports); if(typeof m.exports === "object") { __MODS__[modId].m.exports.__proto__ = m.exports.__proto__; Object.keys(m.exports).forEach(function(k) { __MODS__[modId].m.exports[k] = m.exports[k]; var desp = Object.getOwnPropertyDescriptor(m.exports, k); if(desp && desp.configurable) Object.defineProperty(m.exports, k, { set: function(val) { __MODS__[modId].m.exports[k] = val; }, get: function() { return __MODS__[modId].m.exports[k]; } }); }); if(m.exports.__esModule) Object.defineProperty(__MODS__[modId].m.exports, "__esModule", { value: true }); } else { __MODS__[modId].m.exports = m.exports; } } return __MODS__[modId].m.exports; };
var __REQUIRE_WILDCARD__ = function(obj) { if(obj && obj.__esModule) { return obj; } else { var newObj = {}; if(obj != null) { for(var k in obj) { if (Object.prototype.hasOwnProperty.call(obj, k)) newObj[k] = obj[k]; } } newObj.default = obj; return newObj; } };
var __REQUIRE_DEFAULT__ = function(obj) { return obj && obj.__esModule ? obj.default : obj; };
__DEFINE__(1586268653632, function(require, module, exports) {
const sm2 = require('sm-crypto').sm2;

const addresses = ['https://node1.taas.internetapi.cn'];

// ServerAddr GetServerAddr()
let getServerAddr = function () {
    if (addresses.length === 1) {
        return addresses[0];
    }
    return addresses[Math.floor(Math.random() * addresses.length)];
};

// Cred GetCredential()
// used for network access and data signature
let getCredential = function () {
    let cred = sm2.generateKeyPairHex();

    let publicKey = cred.publicKey;
    let privateKey = cred.privateKey;

    return {
        publicKey: publicKey,
        privateKey: privateKey
    };
};

// HashID StoreEvidence(Data, ServerAddr, Cred)
let storeEvidence = function (data, serverAddr, cred, callback) {

    let url = (serverAddr === undefined ? getServerAddr() : serverAddr);

    let requestData = {
        from: cred.publicKey,
        data: data
    };

    if (typeof (data) === "string") {
        url += '/uploadMessage';
        requestData.sig = signature(data, cred);
        requestData.type = 'text';

        return messagePost(url, requestData, callback);
    } else if (data instanceof File) {
        url += '/uploadFile';
        requestData.sig = signature(data.toString(), cred);

        return filePost(url, requestData, callback);
    } else {
        throw DOMException;
    }
};

// Data QueryEvidence(HashID, ServerAddr, Cred)
let queryEvidence = function (hashId, serverAddr, cred, callback) {

    let url = `${(serverAddr === undefined ? getServerAddr() : serverAddr)}/queryData`;
    return messagePost(url, {hash: hashId}, callback);
};

let signature = function (text, cred) {

    return sm2.doSignature(text, cred.privateKey);
};

let messagePost = function (url, body, callback) {

    let options = {
        url: url,
        method: "POST",
        timeout: 0,
        header: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        data: body,
        success: function (response) {
            // uploadMessage
            // response.data = {code, data: {hash, sig}}
            // queryData
            // response.data = {code, data: {data: {sig, data, text, type}, from, sig, timestamp}}
            console.log(response);
            if (callback) {
                callback(response.data.data);
            }
        }
    };

    wx.request(options);
};

let filePost = function (url, body, callback) {

    let form_data = new FormData();
    for (let i in body) {
        form_data.append(i, body[i]);
    }

    let options = {
        url: url,
        timeout: 0,
        contentType: false,
        mimeType: "multipart/form-data",
        processData: false,
        data: form_data,
        success: function (response) {
            // uploadFile
            // response = {code, data: {hash, sig}}
            console.log(callback);
            if (callback) {
                callback(response.data);
            }
        }
    };

    return $.post(options);
};

module.exports = {
    version: "0.1.1",
    getServerAddr: getServerAddr,
    getCredential: getCredential,
    storeEvidence: storeEvidence,
    queryEvidence: queryEvidence
};
}, function(modId) {var map = {}; return __REQUIRE__(map[modId], modId); })
return __REQUIRE__(1586268653632);
})()
//# sourceMappingURL=index.js.map