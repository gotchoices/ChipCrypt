import { Asymmetric, KeyPairBin, AsymmetricVault, arrayToBase64, base64ToArray } from "chipcryptbase";

/**
 * Implementation of AsymmetricVault for handling asymmetric encryption, decryption, and signing operations.
 */
export class AsymmetricVaultImpl implements AsymmetricVault {
    /**
     * Constructs an instance of AsymmetricVaultImpl.
     * @param _asymmetric An instance of an Asymmetric class to perform cryptographic operations.
     * @param _keyPair The key pair (public and private key) used for encryption and signing.
     */
    constructor (
        private _asymmetric: Asymmetric,
        private _keyPair: KeyPairBin
    ) { }

    /**
     * Asynchronously generates a new AsymmetricVaultImpl instance with a fresh key pair.
     * @param asymmetric An instance of an Asymmetric class.
     * @returns A promise that resolves to an instance of AsymmetricVaultImpl.
     */
    static async generate(asymmetric: Asymmetric): Promise<AsymmetricVaultImpl> {
        const keyPair = await asymmetric.generateKeyPairBin();
        return new AsymmetricVaultImpl(asymmetric, keyPair);
    }

		async getPublicKey(): Promise<Uint8Array> {
			return this._keyPair.publicKey;
		}

		async getPublicKeyAsString(): Promise<string> {
			return arrayToBase64(this._keyPair.publicKey);
		}

    /**
     * Encrypts the given data using the public key.
     * @param data The data to be encrypted, as a string.
     * @returns A promise that resolves to the encrypted data as a string.
     */
    async encrypt(data: string): Promise<string> {
        return await this._asymmetric.encryptWithPublicKey(this._keyPair.publicKey, data);
    }

    /**
     * Decrypts the given data using the private key.
     * @param encryptedDataJson The encrypted data as a string in JSON format.
     * @returns A promise that resolves to the decrypted data as a string.
     */
    async decrypt(encryptedDataJson: string): Promise<string> {
        return await this._asymmetric.decryptWithPrivateKey(this._keyPair.privateKey, encryptedDataJson);
    }

    /**
     * Signs the given data using the private key.
     * @param data The data to be signed, as a string.
     * @returns A promise that resolves to the signature as a base64 encoded string.
     */
    async sign(data: string): Promise<string> {
        return arrayToBase64(
            await this._asymmetric.signDigest(this._keyPair.privateKey, this._asymmetric.generateDigest(data)));
    }

    /**
     * Verifies the given signature against the data using the public key.
     * @param data The original data that was signed, as a string.
     * @param signature The signature to verify, as a base64 encoded string.
     * @returns A promise that resolves to a boolean indicating whether the signature is valid.
     */
    async verify(data: string, signature: string): Promise<boolean> {
        return await this._asymmetric.verifyDigest(this._keyPair.publicKey, this._asymmetric.generateDigest(data), base64ToArray(signature));
    }
}
