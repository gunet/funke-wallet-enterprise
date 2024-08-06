import { DataItem, Verifier } from "@auth0/mdl"
import cbor from 'cbor-x';


export const verifyDeviceResponse = async (encodedDeviceResponse: Uint8Array, trustAnchorCerts: string[], client_id: string, response_uri: string, verifierGeneratedNonce: string, mdocGeneratedNonce: string) => {
	// @ts-ignore
	const getSessionTranscriptBytes = ({ client_id: clientId, response_uri: responseUri, nonce }, mdocGeneratedNonce) => cbor.encode(
		DataItem.fromData([
			null, // DeviceEngagementBytes
			null, // EReaderKeyBytes
			[mdocGeneratedNonce, clientId, responseUri, nonce], // Handover
		]),
	);

	const encodedSessionTranscript = getSessionTranscriptBytes(
		{ client_id, response_uri, nonce: verifierGeneratedNonce },
		mdocGeneratedNonce
	)

	const verifier = new Verifier(trustAnchorCerts);
	const verificationResult = await verifier.verify(encodedDeviceResponse, {
			encodedSessionTranscript,
			disableCertificateChainValidation: false
		}).then(() => true)
		.catch((err: any) => {
			console.log("Verification error");
			console.log(err);
			return false;
		})
	return verificationResult;
}