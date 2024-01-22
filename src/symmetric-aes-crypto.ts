import { Symmetric, arrayToBase64 } from 'chipcryptbase';
import * as crypto from 'crypto';
import { concatenateTypedArrays } from './array-concat';

/**
 * Implementation of the Symmetric interface using AES-256-GCM algorithm in the crypto module.
 * This class provides methods for symmetric key generation, encryption, and decryption.
 */
export class SymmetricImpl implements Symmetric {
    /**
     * Generates a symmetric encryption key.
     * @returns A promise that resolves to a 32-byte random key as a `Uint8Array`.
     */
    async generateKey(): Promise<Uint8Array> {
        return crypto.randomBytes(32);
    }

    /**
     * Encrypts the provided content using AES-256-GCM algorithm.
     * @param key The symmetric key as a `Uint8Array`.
     * @param content The content to be encrypted, as a string.
     * @returns A promise that resolves to the encrypted content. The result includes
     * the initialization vector (IV), the authentication tag, and the encrypted data, concatenated in this order.
     */
    async encrypt(key: Uint8Array, content: string): Promise<Uint8Array> {
        const iv = crypto.randomBytes(16); // Initialization vector
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

        const encrypted = concatenateTypedArrays(
            cipher.update(content, 'utf8'),
            cipher.final(),
        );

        const tag = cipher.getAuthTag();

        // Combine the IV, encrypted data, and authentication tag into a single buffer
        return concatenateTypedArrays(iv, tag, encrypted);
    }

    /**
     * Decrypts the provided encrypted data using AES-256-GCM algorithm.
     * @param key The symmetric key as a `Uint8Array`.
     * @param encrypted The encrypted data, including the IV, tag, and the actual encrypted content.
     * @returns A promise that resolves to the decrypted content as a string.
     * The input should be a concatenation of the IV, the authentication tag, and the encrypted data, in this order.
     */
    async decrypt(key: Uint8Array, encrypted: Uint8Array): Promise<string> {
        const iv = encrypted.slice(0, 16);
        const tag = encrypted.slice(16, 32);
        const encData = encrypted.slice(32);

        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);

        const decrypted = concatenateTypedArrays(
            decipher.update(encData),
            decipher.final(),
        );

        return arrayToBase64(decrypted);
    }
}
