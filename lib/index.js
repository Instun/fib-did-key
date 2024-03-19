var crypto = require('crypto');
var multibase = require('multibase');
var base64 = require('base64');
var util = require('util');

const { config, types } = require("./algs");
const methods = ['verificationMethod', 'assertionMethod', 'authentication', 'capabilityInvocation', 'capabilityDelegation', 'keyAgreement'];

function fingerprint(k) {
    var jwk;
    if (k instanceof crypto.KeyObject) {
        jwk = k.export({ format: "jwk" });
        if (k.type === 'private')
            k = crypto.createPublicKey(k);
    }
    else {
        jwk = k;
        k = crypto.createPublicKey({ key: k });
    }

    var cfg = config[jwk.crv];
    var bid = Buffer.concat([cfg.head, k.export({ format: "raw", type: 'compressed' })]);
    var mid = multibase.encode(bid, 'base58btc');
    return mid;
}

function gen_doc(id, keys, opts) {
    var doc = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": id
    };

    var ks = [];

    keys.forEach(k => {
        var pk = {};
        var key = {};

        key.id = pk.id = id + "#" + fingerprint(k);
        key.type = pk.type = "JsonWebKey2020";
        key.controller = pk.controller = id;

        if (k.type === 'private') {
            key.publicKeyJwk = pk.publicKeyJwk = crypto.createPublicKey(k).export({ format: "jwk" });
            key.privateKeyJwk = k.export({ format: "jwk" });
        } else
            key.publicKeyJwk = pk.publicKeyJwk = k.export({ format: "jwk" });

        ks.push(key);

        var methods = config[key.publicKeyJwk.crv].methods;
        var added = false;
        methods.forEach(m => {
            var mk = doc[m];
            if (!mk)
                mk = doc[m] = [];

            if (added)
                mk.push(pk.id);
            else {
                added = true;
                mk.push(pk);
            }
        });
    });

    return {
        didDocument: doc,
        keys: ks
    };
}

function resolve(id, opts) {
    var ids = id.split('#');

    id = ids[0];
    opts = opts || {};
    if (id.substr(0, 8) !== 'did:key:')
        throw new Error("invalid key id format");

    var bid = multibase.decode(id.substr(8));
    var t = types[bid.readUInt16BE(0)];
    if (!t)
        throw new Error("invalid key id format");

    var keys = [];

    var ppk = crypto.createPublicKey({
        key: bid.slice(2),
        format: "raw",
        namedCurve: t
    });
    keys.push(ppk);

    if (ppk.asymmetricKeyType == "ed25519")
        keys.push(crypto.createPublicKey({
            key: ppk,
            toX25519: true
        }));

    return gen_doc(id, keys, opts);
}

function generate(type, opts) {
    opts = opts || {};
    var sk;
    var mid;
    var id;
    var secure = opts.secure;

    var keys = [];

    if (secure) {
        if (!util.isBuffer(secure))
            secure = base64.decode(secure);

        sk = crypto.createPrivateKey({
            key: secure,
            format: "raw",
            namedCurve: type
        });
    } else if (type == 'ed25519' || type == 'x25519')
        sk = crypto.generateKeyPairSync(type).privateKey;
    else
        sk = crypto.generateKeyPairSync('ec', {
            namedCurve: type
        }).privateKey;

    keys.push(sk);

    if (sk.asymmetricKeyType == "ed25519")
        keys.push(crypto.createPrivateKey({
            key: sk,
            toX25519: true
        }));

    mid = fingerprint(sk);

    id = 'did:key:' + mid;

    return gen_doc(id, keys, opts);
}

function sign(data, key) {
    var sk = key instanceof crypto.KeyObject ? key.export({ format: "jwk" }) : key;
    var cfg = config[sk.crv];
    var hdr = {
        alg: cfg.alg,
        b64: false,
        crit: ["b64"]
    };

    var _hdr = base64.encode(JSON.stringify(hdr), true) + '.';
    var _data = Buffer.concat([Buffer.from(_hdr), data]);
    return _hdr + "." + base64.encode(crypto.sign(cfg.md, _data, {
        key: key,
        dsaEncoding: "ieee-p1363"
    }), true);
}

function verify(data, sig, key) {
    var pk = key instanceof crypto.KeyObject ? key.export({ format: "jwk" }) : key;
    var cfg = config[pk.crv];
    var s = sig.split('.');

    if (s.length !== 3 || s[1] !== '')
        throw new Error("invalid signation format");

    var hdr = JSON.parse(base64.decode(s[0]).toString());
    if (hdr.alg !== cfg.alg)
        throw new Error(`invalid signation algorithm "${hdr.alg}"`);

    if (hdr.b64 !== false || hdr.crit.length !== 1 || hdr.crit[0] !== "b64")
        throw new Error("invalid signation format");

    var _data = Buffer.concat([Buffer.from(s[0] + "."), data]);

    return crypto.verify(cfg.md, _data, {
        key: key,
        dsaEncoding: "ieee-p1363"
    }, base64.decode(s[2]));
}

module.exports = {
    generate,
    resolve,
    sign,
    verify,
    fingerprint
};
