import { SymmetricVault, Symmetric } from "chipcryptbase";

/**
 * Implementation of a symmetric vault interface which keeps or generates the private key in memory.
 * WARNING: Obviously not secure if memory is accessible.
 */
export class SymmetricVaultImpl implements SymmetricVault {
	/**
	 * Creates a new instance of the SymmetricVaultImpl class.
	 * @param _symmetric The symmetric encryption interface.
	 * @param _key The encryption key.
	 */
	constructor(
		private _symmetric: Symmetric,
		private _key: Uint8Array
	) { }

	/**
	 * Gets the encryption key.
	 * @returns The encryption key.
	 */
	getKey() {
		return this._key;
	}

	/**
	 * Generates a SymmetricVault instance containing a randomly generated new key.
	 * @param symmetric The symmetric encryption interface.
	 * @returns A promise that resolves with the new SymmetricVault instance.
	 */
	static async generate(symmetric: Symmetric): Promise<SymmetricVault> {
		const key = await symmetric.generateKey();
		return new SymmetricVaultImpl(symmetric, key);
	}

	/**
	 * Encrypts the specified content.
	 * @param content The content to encrypt.
	 * @returns A promise containing the encrypted content as a Uint8Array.
	 */
	encrypt(content: string) {
		return this._symmetric.encrypt(this._key, content);
	}

	/**
	 * Decrypts the specified encrypted content.
	 * @param encrypted The encrypted content to decrypt as a Uint8Array.
	 * @returns A promise containing the decrypted content as a string.
	 */
	decrypt(encrypted: Uint8Array) {
		return this._symmetric.decrypt(this._key, encrypted);
	}
}
