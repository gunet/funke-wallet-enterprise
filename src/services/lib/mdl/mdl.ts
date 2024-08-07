import { MDoc, parse } from "@auth0/mdl";
import * as cbor from 'cbor-x';
import * as jose from 'jose';

export const parseMsoMdocCredential = async (mso_mdoc_cred: string, docType: string): Promise<MDoc> => {

	const credentialBytes = jose.base64url.decode(mso_mdoc_cred);
	const issuerSigned = await cbor.decode(credentialBytes);
	const m = {
		version: '1.0',
		documents: [new Map([
			['docType', docType],
			['issuerSigned', issuerSigned]
		])],
		status: 0
	}
	const encoded = cbor.encode(m) as Uint8Array;
	return parse(encoded);
}

export const convertToJSONWithMaps = (obj: any) => {
	return JSON.parse(JSON.stringify(obj, (_key, value) => {
		if (value instanceof Map) {
			const obj = {};
			for (let [k, v] of value) {
				// @ts-ignore
				obj[k] = v;
			}
			return obj;
		}
		return value;
	}));
}
