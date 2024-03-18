var test = require('test');
test.setup();

var multibase = require('multibase');
var base64 = require('base64');

var keys = require('./keys');

var did_key = require('..');

describe('did-key', () => {
    for (var k in keys)
        describe(k, () => {
            var data = keys[k];

            it('resolve', () => {
                data.forEach(d => {
                    var r = did_key.resolve(d.id);
                    assert.deepEqual(d["application/did+json"].didDocument, r.didDocument);

                    r = did_key.resolve(r.keys[0].id);
                    assert.deepEqual(d["application/did+json"].didDocument, r.didDocument);
                });
            });

            it('generate', () => {
                data.forEach(d => {
                    var r = did_key.generate(d.type, {
                        secure: d.secure
                    });
                    assert.deepEqual(d["application/did+json"].didDocument, r.didDocument);
                    assert.deepEqual(d["application/did+json"].keys, r.keys);
                });
            });

            if (k !== 'x25519')
                it('sign/verify', () => {
                    data.forEach(d => {
                        var key = did_key.generate(d.type, {
                            secure: d.secure
                        }).keys[0];

                        var sig = did_key.sign(Buffer.from("hello world."), key.privateKeyJwk);
                        var verify = did_key.verify(Buffer.from("hello world."), sig, key.publicKeyJwk);

                        assert.ok(verify);
                    });
                });
        });
});

test.run(console.DEBUG);
