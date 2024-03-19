const ed25519 = [
  require('./ed25519/did-key-ed25519-case-0.json'),
  require('./ed25519/did-key-ed25519-case-1.json'),
  require('./ed25519/did-key-ed25519-case-2.json'),
];

const x25519 = [
  require('./x25519/did-key-x25519-case-0.json'),
  require('./x25519/did-key-x25519-case-1.json'),
  require('./x25519/did-key-x25519-case-2.json'),
];

const secp256k1 = [
  require('./secp256k1/did-key-secp256k1-case-0.json'),
  require('./secp256k1/did-key-secp256k1-case-1.json'),
  require('./secp256k1/did-key-secp256k1-case-2.json'),
];

const bls12381 = [
  require('./bls12381/did-key-bls12381-case-0.json'),
  require('./bls12381/did-key-bls12381-case-1.json'),
  require('./bls12381/did-key-bls12381-case-2.json'),
];

const secp256r1 = [
  require('./secp256r1/did-key-secp256r1-case-0.json'),
  require('./secp256r1/did-key-secp256r1-case-1.json'),
  require('./secp256r1/did-key-secp256r1-case-2.json'),
];

const secp384r1 = [
  require('./secp384r1/did-key-secp384r1-case-0.json'),
  require('./secp384r1/did-key-secp384r1-case-1.json'),
  require('./secp384r1/did-key-secp384r1-case-2.json'),
];

const secp521r1 = [
  require('./secp521r1/did-key-secp521r1-case-0.json'),
  require('./secp521r1/did-key-secp521r1-case-1.json'),
  require('./secp521r1/did-key-secp521r1-case-2.json'),
];

const sm2 = [
  require('./sm2/did-key-sm2-case-0.json'),
  require('./sm2/did-key-sm2-case-1.json'),
  require('./sm2/did-key-sm2-case-2.json'),
];

module.exports = {
  ed25519,
  x25519,
  secp256r1,
  secp384r1,
  secp521r1,
  secp256k1,
  sm2,
  // bls12381,
};
