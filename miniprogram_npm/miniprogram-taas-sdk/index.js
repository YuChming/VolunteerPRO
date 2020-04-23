module.exports = (function() {
var __MODS__ = {};
var __DEFINE__ = function(modId, func, req) { var m = { exports: {}, _tempexports: {} }; __MODS__[modId] = { status: 0, func: func, req: req, m: m }; };
var __REQUIRE__ = function(modId, source) { if(!__MODS__[modId]) return require(source); if(!__MODS__[modId].status) { var m = __MODS__[modId].m; m._exports = m._tempexports; var desp = Object.getOwnPropertyDescriptor(m, "exports"); if (desp && desp.configurable) Object.defineProperty(m, "exports", { set: function (val) { if(typeof val === "object" && val !== m._exports) { m._exports.__proto__ = val.__proto__; Object.keys(val).forEach(function (k) { m._exports[k] = val[k]; }); } m._tempexports = val }, get: function () { return m._tempexports; } }); __MODS__[modId].status = 1; __MODS__[modId].func(__MODS__[modId].req, m, m.exports); } return __MODS__[modId].m.exports; };
var __REQUIRE_WILDCARD__ = function(obj) { if(obj && obj.__esModule) { return obj; } else { var newObj = {}; if(obj != null) { for(var k in obj) { if (Object.prototype.hasOwnProperty.call(obj, k)) newObj[k] = obj[k]; } } newObj.default = obj; return newObj; } };
var __REQUIRE_DEFAULT__ = function(obj) { return obj && obj.__esModule ? obj.default : obj; };
__DEFINE__(1587621840871, function(require, module, exports) {
const sm2 = require('sm-crypto').sm2;

const addresses = ['https://node0.taas.internetapi.cn'];

// ServerAddr GetServerAddr()
/**
 * Get TaaS backend server address.
 *
 * @return an address of a TaaS backend server. If there are multiple available servers, return a random one.
 */
function getServerAddr() {
    if (addresses.length === 1) {
        return addresses[0];
    }
    return addresses[Math.floor(Math.random() * addresses.length)];
};

// AccessToken register(InvitationCode, ServerAddr, Cred)
/**
 * Register with invitation code and public key, get the access token.
 *
 * @param invitationCode    the invitation code
 * @param serverAddr        the server address
 * @param credential        an object that is returned by sdk.getCredential()
 * @param callback          a function called when the server has responded the sdk.register request.
 * @return null.
 */
function register(invitationCode, serverAddr, credential, callback){
    var url = serverAddr;
    if (!url) url = getServerAddr();
    url = url + "/auth/register";

    var formData = {
        from: credential.publicKey,
        verifyCode: invitationCode
    };

    var params = {
        url: url,
        method: "POST",
        timeout: 0,
        header: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        data: formData
    };
    params.success = (res) => {
        if (res.data.code !== 0){
            callback(new Error(res.data.message));
            return ;
        }

        var token = res.data.data.accessToken;
        callback(undefined, token);
    };
    params.fail = (res) => {callback(new Error("network error"));};
    wx.request(params);
};

// Cred GetCredential()
/**
 * Generate a public key, private key and credential, i.e. access token
 *
 * @return null.
 */
function getCredential(invitationCode, serverAddr, callback) {
    let cred = sm2.generateKeyPairHex();
    
    register(invitationCode, serverAddr, cred, (err, data) => {
        if (err) callback(err);
        var r = {
            publicKey: cred.publicKey,
            privateKey: cred.privateKey,
            credential: data
        };
        callback(undefined, r);
    });
};

/**
 * Get the signature of given message by a private key.
 *
 * @param text the message to make signature
 * @param credential a public key and private key pair
 * @return the signature of given message.
 */
function signature(text, credential) {
    return sm2.doSignature(text, credential.privateKey);
};

// HashID StoreEvidence(Data, ServerAddr, Cred)
/**
 * Store evidence of the data in the TaaS backend.
 *
 * @param data          the message to be stored
 * @param serverAddr    the server address
 * @param credential    an object that is returned by sdk.getCredential()
 * @param callback      a function called when the server has responded the sdk.storeEvidence request.
 * @return null.
 */
function storeEvidence(data, serverAddr, credential, callback){
    var text, path;
    if (typeof data === "object"){
        text = data.text;
        path = data.path;
    } else if (typeof data === "string"){
        text = data;
    } else {
        throw new Error(`unidentified type of data: ${typeof data}`);
    };

    if (!path && !text)
        throw new Error("no data to store");
    if (!credential)
        throw new Error("no credential");
    if (!callback)
        throw new Error("no callback");
    
    var sig;
    if (text){
        sig = signature(text, credential);
    } else {
        sig = signature(path, credential);
    }

    var url = serverAddr;
    if (!url) url = getServerAddr();

    if (!path){
        url = url + "/uploadMessage";
        var formData = {
            from: credential.publicKey,
            data: text,
            sig: sig,
            accessToken: credential.credential
        };

        var params = {
            url: url,
            method: "POST",
            timeout: 0,
            header: {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            data: formData
        };
        
        params.success = (res) => {
            if (res.data.code !== 0){
                callback(new Error(res.data.message));
                return ;
            }
            callback(undefined, res.data.data);
        };
        params.fail = () => {callback(new Error("network error"));};
        wx.request(params);
    } else {
        url = url + "/uploadFile";
        var formData = {
            from: credential.publicKey,
            sig: sig,
            accessToken: credential.credential
        };
        if (text) formData.text = text;

        var params = {
            url: url,
            method: 'POST',
            name: "data",
            filePath: path,
            header: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            formData: formData
        };
        params.success = (res) => {
            var data = JSON.parse(res.data);
            if (data.code !== 0){
                callback(new Error(data.message));
                return ;
            }
            callback(undefined, data.data);
        };
        params.fail = () => {callback(new Error("network error"));};
        wx.uploadFile(params);
    };
};

// Data QueryEvidence(HashID, ServerAddr, Cred)
/**
 * Query the data according to a hash ID.
 *
 * @param hashID        the hash value to be queried
 * @param serverAddr    the server address
 * @param credential    an object that is returned by sdk.getCredential()
 * @param callback      a function called when the server has responded the sdk.queryEvidence request.
 * @return null.
 */
 function queryEvidence(hashId, serverAddr, credential, callback){
    if (!callback)
        throw new Error("no callback");
    
    var url = serverAddr;
    if (!url) url = getServerAddr();
    url = url + "/queryData";

    var params = {
        url: url,
        method: "POST",
        timeout: 0,
        header: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        data: {
            hash: hashId,
            from: credential.publicKey,
            accessToken: credential.credential
        }
    };

    params.success = (res) => {
        if (res.data.code !== 0){
            callback(new Error(res.data.message));
            return ;
        }
        var data = res.data.data;
        var d = data.data;
        if (!d.type || d.type === "text"){
            d.text = d.data;
            delete d.data;
        };
        callback(undefined, data);
    };
    params.fail = () => {
        callback(new Error("network error"));
    };
    wx.request(params);
};

/**
 * List current smart contract list of given user access token and server address.
 *
 * @param serverAddr    the server address
 * @param credential    an object that is returned by sdk.getCredential()
 * @param callback      a function called when the server has responded the sdk.getContractList request.
 * @return null.
 */
function getContractList(serverAddr, credential, callback) {
    if (!serverAddr) serverAddr = getServerAddr();
    const url = `${serverAddr}/contract/listContractProcess`;
    
    wx.request({
        url: url,
        method: "POST",
        header: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        data: {
            from: credential.publicKey,
            accessToken: credential.credential
        },
        success: function(res) {
            if (res.data.code !== 0){
                callback(new Error(res.data.message));
                return ;
            }
            callback(undefined, res.data.data);
        },
        fail: function(res) {
            callback(new Error("network error"));
        }
    });
};

/**
 * Execute a smart contract by given contract ID and action
 *
 * @param contractInfo  an object containing contract ID and contract action to execute
 * @param serverAddr    the server address
 * @param credential    an object that is returned by sdk.getCredential()
 * @param callback      a function called when the server has responded the sdk.getContractList request.
 * @return null.
 */
function executeContract(contractInfo, serverAddr, credential, callback) {
    if (!serverAddr) serverAddr = getServerAddr();
    var url = `${serverAddr}/contract/executeContract`;
    var data = {
        from: credential.publicKey,
        accessToken: credential.credential,
        contractID: contractInfo.id,
        operation: contractInfo.method,
        arg: contractInfo.arg
    };
    
    wx.request({
        url: url,
        method: "POST",
        data: data,
        header: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        success: function(res) {
            if (res.data.code !== 0){
                callback(new Error(res.data.message));
                return ;
            }
            callback(undefined, res.data.data);
        },
        fail: function(res) {
            callback(new Error("network error"));
        }
    });
};

function promisify(func){
    function wrapped_func(){
        const args = arguments;
        return new Promise((resolve, reject) => {
            func(...args, (err, data) => {
                if (err) reject(err);
                resolve(data);
            });
        });
    };
    return wrapped_func;
};

const getCredentialP = promisify(getCredential);
const storeEvidenceP = promisify(storeEvidence);
const queryEvidenceP = promisify(queryEvidence);
const getContractListP = promisify(getContractList);
const executeContractP = promisify(executeContract);

module.exports = {
    version: "1.4.2",
    getServerAddr: getServerAddr,
    getCredential: getCredential,
    storeEvidence: storeEvidence,
    queryEvidence: queryEvidence,
    getContractList: getContractList,
    executeContract: executeContract,
    promises: {
        getServerAddr: getServerAddr,
        getCredential: getCredentialP,
        storeEvidence: storeEvidenceP,
        queryEvidence: queryEvidenceP,
        getContractList: getContractListP,
        executeContract: executeContractP
    }
};

}, function(modId) {var map = {}; return __REQUIRE__(map[modId], modId); })
return __REQUIRE__(1587621840871);
})()
//# sourceMappingURL=index.js.map