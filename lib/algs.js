const methods_all = ['verificationMethod', 'assertionMethod', 'authentication', 'capabilityInvocation', 'capabilityDelegation', 'keyAgreement'];
const methods_ka = ['verificationMethod', 'keyAgreement'];
const methods_noka = ['verificationMethod', 'assertionMethod', 'authentication', 'capabilityInvocation', 'capabilityDelegation'];

const config = {
    Ed25519: {
        head: new Buffer([0xed, 0x01]),
        compress: false,
        alg: "EdDSA",
        methods: methods_noka
    },
    X25519: {
        head: new Buffer([0xec, 0x01]),
        compress: false,
        methods: methods_ka
    },

    "P-256": {
        head: new Buffer([0x80, 0x24]),
        compress: true,
        alg: "ES256",
        methods: methods_all,
        md: "SHA256"
    },
    "P-384": {
        head: new Buffer([0x81, 0x24]),
        compress: true,
        alg: "ES384",
        methods: methods_all,
        md: "SHA384"
    },
    "P-521": {
        head: new Buffer([0x82, 0x24]),
        compress: true,
        alg: "ES512",
        methods: methods_all,
        md: "SHA512"
    },

    "SM2": {
        head: new Buffer([0x86, 0x24]),
        compress: true,
        alg: "SM2SM3",
        methods: methods_all,
        md: "SM3"
    },

    secp256k1: {
        head: new Buffer([0xe7, 0x01]),
        compress: true,
        alg: "ES256K",
        methods: methods_all,
        md: "SHA256"
    },

    Bls12381G1: {
        head: new Buffer([0xea, 0x01]),
        compress: false,
        methods: methods_noka
    },
    Bls12381G2: {
        head: new Buffer([0xeb, 0x01]),
        compress: false,
        methods: methods_noka
    },
    bls12381: {
        head: new Buffer([0xee, 0x01])
    },
};

const types = {
    0xed01: 'Ed25519',
    0xec01: 'X25519',

    0x8024: 'P-256',
    0x8124: 'P-384',
    0x8224: 'P-521',

    0x8624: 'SM2',

    0xe701: 'secp256k1',

    0xea01: 'Bls12381G1', // G1
    0xeb01: 'Bls12381G2', // G2
    0xee01: 'bls12381', // G1&G2
};

module.exports = {
    config,
    types
};