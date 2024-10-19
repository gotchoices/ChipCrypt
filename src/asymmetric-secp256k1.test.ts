import { AsymmetricImpl } from './asymmetric-secp256k1';
import * as secp256k1 from 'secp256k1';
import { arrayToBase64, base64ToArray } from 'chipcryptbase';

describe('AsymmetricImpl', () => {
  let asymmetric: AsymmetricImpl;

  beforeEach(() => {
    asymmetric = new AsymmetricImpl();
  });

  test('generateKeyPairBin should create valid secp256k1 key pair', async () => {
    const keyPair = await asymmetric.generateKeyPairBin();
    expect(secp256k1.privateKeyVerify(keyPair.privateKey)).toBe(true);
    expect(secp256k1.publicKeyVerify(keyPair.publicKey)).toBe(true);
  });

  test('generateKeyPair should create base64 encoded key pair', async () => {
    const keyPair = await asymmetric.generateKeyPair();
    expect(typeof keyPair.privateKey).toBe('string');
    expect(typeof keyPair.publicKey).toBe('string');
    expect(() => base64ToArray(keyPair.privateKey)).not.toThrow();
    expect(() => base64ToArray(keyPair.publicKey)).not.toThrow();
  });

  test('signDigest and verifyDigest should work correctly', async () => {
    const keyPair = await asymmetric.generateKeyPairBin();
    const message = 'Hello, World!';
    const digest = asymmetric.generateDigest(message);
    const signature = await asymmetric.signDigest(keyPair.privateKey, digest);
    const isValid = await asymmetric.verifyDigest(keyPair.publicKey, digest, signature);
    expect(isValid).toBe(true);
  });

  test('encryptWithPublicKey and decryptWithPrivateKey should work correctly', async () => {
    const keyPair = await asymmetric.generateKeyPairBin();
    const message = 'Secret message';
    const encrypted = await asymmetric.encryptWithPublicKey(keyPair.publicKey, message);
    const decrypted = await asymmetric.decryptWithPrivateKey(keyPair.privateKey, encrypted);
    expect(decrypted).toBe(message);
  });

  test('generateDigest should create consistent digests', () => {
    const message = 'Hello, World!';
    const digest1 = asymmetric.generateDigest(message);
    const digest2 = asymmetric.generateDigest(message);
    expect(arrayToBase64(digest1)).toBe(arrayToBase64(digest2));
  });

  test('verifyDigest should fail with incorrect signature', async () => {
    const keyPair = await asymmetric.generateKeyPairBin();
    const message = 'Hello, World!';
    const digest = asymmetric.generateDigest(message);
    const signature = await asymmetric.signDigest(keyPair.privateKey, digest);
    const tamperedSignature = new Uint8Array(signature);
    tamperedSignature[0] ^= 1; // Flip a bit in the signature
    const isValid = await asymmetric.verifyDigest(keyPair.publicKey, digest, tamperedSignature);
    expect(isValid).toBe(false);
  });

  test('decryptWithPrivateKey should fail with incorrect private key', async () => {
    const keyPair1 = await asymmetric.generateKeyPairBin();
    const keyPair2 = await asymmetric.generateKeyPairBin();
    const message = 'Secret message';
    const encrypted = await asymmetric.encryptWithPublicKey(keyPair1.publicKey, message);
    await expect(asymmetric.decryptWithPrivateKey(keyPair2.privateKey, encrypted)).rejects.toThrow();
  });
});
