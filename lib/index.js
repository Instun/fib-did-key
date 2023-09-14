var crypto = require('crypto');
var multibase = require('multibase');
var base64 = require('base64');
var hash = require('hash');
var util = require('util');

const { config, types } = require("./algs");
const methods = ['verificationMethod', 'assertionMethod', 'authentication', 'capabilityInvocation', 'capabilityDelegation', 'keyAgreement'];

function fingerprint(k) {
    var cfg = config[k.curve];
    var bid = Buffer.concat([cfg.head, base64.decode(k.json({
        compress: cfg.compress
    }).x)]);
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

        if (k.isPrivate()) {
            key.publicKeyJwk = pk.publicKeyJwk = k.publicKey.json();
            key.privateKeyJwk = k.json();
        } else
            key.publicKeyJwk = pk.publicKeyJwk = k.json();

        ks.push(key);

        var methods = config[k.curve].methods;
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

    if (t == "bls12381") {
        keys.push(crypto.PKey.from({
            "kty": "EC",
            "crv": "Bls12381G1",
            "x": bid.slice(2, 50).base64()
        }));

        keys.push(crypto.PKey.from({
            "kty": "EC",
            "crv": "Bls12381G2",
            "x": bid.slice(50).base64()
        }));
    } else {
        var ppk = crypto.PKey.from({
            "kty": "EC",
            "crv": t,
            "x": bid.slice(2).base64()
        });
        keys.push(ppk);

        if (t == "Ed25519")
            keys.push(ppk.toX25519());
    }

    return gen_doc(id, keys, opts);
}

function generate(type, opts) {
    opts = opts || {};
    var crv = type == 'bls12381' ? 'Bls12381G1' : type;
    var sk;
    var mid;
    var id;
    var secure = opts.secure;

    var keys = [];

    if (secure) {
        if (util.isBuffer(secure))
            secure = base64.encode(secure);

        sk = crypto.PKey.from({
            "kty": "EC",
            "crv": crv,
            "d": secure
        });
    } else
        sk = crypto.generateKey(crv);

    keys.push(sk);

    if (sk.curve == "Ed25519")
        keys.push(sk.toX25519());

    if (type == 'bls12381') {
        var jwk = sk.json();
        var sk2 = crypto.PKey.from({
            "kty": "EC",
            "crv": "Bls12381G2",
            "d": jwk.d
        });
        keys.push(sk2);

        var bid = Buffer.concat([config.bls12381.head, base64.decode(jwk.x), base64.decode(sk2.json().x)]);
        mid = multibase.encode(bid, 'base58btc');
    } else mid = fingerprint(sk);

    id = 'did:key:' + mid;

    return gen_doc(id, keys, opts);
}

function sign(data, key) {
    var sk = key instanceof crypto.PKey ? key : crypto.PKey.from(key);
    var cfg = config[sk.curve];
    var hdr = {
        alg: cfg.alg,
        b64: false,
        crit: ["b64"]
    };

    var _hdr = base64.encode(JSON.stringify(hdr), true) + '.';

    var _data = Buffer.concat([_hdr, data]);

    if (cfg.md)
        _data = hash.digest(hash[cfg.md], _data).digest();

    return _hdr + "." + base64.encode(sk.sign(_data, {
        format: 'bin'
    }), true);
}

function verify(data, sig, key) {
    var pk = key instanceof crypto.PKey ? key : crypto.PKey.from(key);
    var cfg = config[pk.curve];
    var s = sig.split('.');

    if (s.length !== 3 || s[1] !== '')
        throw new Error("invalid signation format");

    var hdr = JSON.parse(base64.decode(s[0]).toString());
    if (hdr.alg !== cfg.alg)
        throw new Error(`invalid signation algorithm "${hdr.alg}"`);

    if (hdr.b64 !== false || hdr.crit.length !== 1 || hdr.crit[0] !== "b64")
        throw new Error("invalid signation format");

    var _data = Buffer.concat([s[0], ".", data]);

    if (cfg.md)
        _data = hash.digest(hash[cfg.md], _data).digest();

    return pk.verify(_data, base64.decode(s[2]), {
        format: "bin"
    });
}

module.exports = {
    generate,
    resolve,
    sign,
    verify,
    fingerprint
};
