import { Asymmetric, KeyPair, KeyPairBin, arrayToBase64, base64ToArray } from 'chipcryptbase';
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'crypto';
import * as secp256k1 from 'secp256k1';
import { concatenateTypedArrays } from './array-concat';

export class AsymmetricImpl implements Asymmetric {
	async generateKeyPairBin(): Promise<KeyPairBin> {
		let privateKey: Uint8Array;
		do {
			privateKey = randomBytes(32);
		} while (!secp256k1.privateKeyVerify(privateKey));

		const publicKey = secp256k1.publicKeyCreate(privateKey);
		return { privateKey, publicKey };
	}

	async generateKeyPair(): Promise<KeyPair> {
		const pair = await this.generateKeyPairBin();
		return { privateKey: arrayToBase64(pair.privateKey), publicKey: arrayToBase64(pair.publicKey) };
	}

	generateDigest(content: string): Uint8Array {
		return createHash('sha256').update(content).digest();
	}

	async signDigest(privateKey: Uint8Array, digest: Uint8Array): Promise<Uint8Array> {
		const signedData = secp256k1.ecdsaSign(digest, privateKey);
		return signedData.signature;
	}

	async verifyDigest(publicKey: Uint8Array, digest: Uint8Array, signature: Uint8Array): Promise<boolean> {
		return secp256k1.ecdsaVerify(signature, digest, publicKey);
	}

	async encryptWithPublicKey(publicKey: Uint8Array, data: string): Promise<string> {
		const ephemeralPair = await this.generateKeyPairBin();
		const sharedSecret = secp256k1.ecdh(publicKey, ephemeralPair.privateKey);
		const hash = createHash('sha256').update(sharedSecret).digest();
		const iv = randomBytes(16);
		const cipher = createCipheriv('aes-256-gcm', hash, iv);
		const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
		const authTag = cipher.getAuthTag();

		return JSON.stringify({
			ephemeralPublicKey: arrayToBase64(ephemeralPair.publicKey),
			iv: arrayToBase64(iv),
			encryptedData: arrayToBase64(encrypted),
			authTag: arrayToBase64(authTag)
		});
	}

	async decryptWithPrivateKey(privateKey: Uint8Array, encryptedDataJson: string): Promise<string> {
		const encryptedObj = JSON.parse(encryptedDataJson);
		const encryptedData = {
			ephemeralPublicKey: base64ToArray(encryptedObj.ephemeralPublicKey),
			iv: base64ToArray(encryptedObj.iv),
			encryptedData: base64ToArray(encryptedObj.encryptedData),
			authTag: base64ToArray(encryptedObj.authTag)
		};

		const sharedSecret = secp256k1.ecdh(encryptedData.ephemeralPublicKey, privateKey);
		const hash = createHash('sha256').update(sharedSecret).digest();
		const decipher = createDecipheriv('aes-256-gcm', hash, encryptedData.iv);
		decipher.setAuthTag(encryptedData.authTag);

		const decrypted = concatenateTypedArrays(
			decipher.update(encryptedData.encryptedData),
			decipher.final()
		);
		return new TextDecoder().decode(decrypted);
	}
}
