export function concatenateTypedArrays(...arrays: Uint8Array[]) {
	const totalLength = arrays.reduce((length, array) => length + array.length, 0);
	const result = new Uint8Array(totalLength);
	let offset = 0;
	for (const array of arrays) {
		result.set(array, offset);
		offset += array.length;
	}
	return result;
}
