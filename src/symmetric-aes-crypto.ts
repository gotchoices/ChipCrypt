import { Symmetric } from 'chipcryptbase';
import * as crypto from 'crypto';

export class SymmetricImpl implements Symmetric {
	generateKey(): Buffer {
		return crypto.randomBytes(32);
	}

	encryptContent(content: string, key: Buffer): Uint8Array {
		const iv = crypto.randomBytes(16); // Initialization vector
		const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

		const encrypted = Buffer.concat([
			cipher.update(content, 'utf8'),
			cipher.final(),
		]);

		const tag = cipher.getAuthTag();

		// Combine the IV, encrypted data, and authentication tag into a single buffer
		return Buffer.concat([iv, tag, encrypted]);
	}

	decryptContent(encrypted: Uint8Array, key: Buffer): string {
		const iv = encrypted.slice(0, 16);
		const tag = encrypted.slice(16, 32);
		const encData = encrypted.slice(32);

		const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
		decipher.setAuthTag(tag);

		const decrypted = Buffer.concat([
			decipher.update(encData),
			decipher.final(),
		]);

		return decrypted.toString('utf8');
	}

	encryptObject(obj: any, key: Buffer): Uint8Array {
		const content = JSON.stringify(obj);
		return this.encryptContent(content, key);
	}

	decryptObject(encrypted: Uint8Array, key: Buffer): any {
		const content = this.decryptContent(encrypted, key);
		return JSON.parse(content);
	}
}
