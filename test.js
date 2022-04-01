const crypto = require('crypto');
const fs = require('fs');

let EC = require('elliptic').ec;

let ec = new EC('secp256k1');

const key = ec.genKeyPair();

var msgHash = "AzKam";

var signature = key.sign(msgHash);

let der = signature.toDER("hex");

console.log(signature);


let clePublique = key.getPublic().encode('hex');

let cleImporte = ec.keyFromPublic(clePublique, 'hex');

console.log(cleImporte.verify(msgHash, signature))


const fileBuffer = fs.readFileSync('image.jpg');
const hashSum = crypto.createHash('sha256');
hashSum.update(fileBuffer);

const hex = hashSum.digest('hex');

console.log(hex);