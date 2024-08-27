import { inject, injectable } from "inversify";
import { Request, Response } from 'express'
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "./interfaces";
import { VerifiableCredentialFormat } from "../types/oid4vci";
import { AuthorizationRequestQueryParamsSchemaType } from "../types/oid4vci";
import { TYPES } from "./types";
import { importJWK, importX509, JWK, jwtVerify, SignJWT } from "jose";
import { KeyLike, createHash, randomUUID, verify, X509Certificate } from "crypto";
import base64url from "base64url";
import { PresentationDefinitionType, PresentationSubmission } from "@wwwallet/ssi-sdk";
import 'reflect-metadata';
import { JSONPath } from "jsonpath-plus";
import { Repository } from "typeorm";
import { ClaimRecord, PresentationClaims, VerifiablePresentationEntity } from "../entities/VerifiablePresentation.entity";
import AppDataSource from "../AppDataSource";
import { DidKeyResolverService } from "./DidKeyResolverService";
import { HasherAlgorithm, HasherAndAlgorithm, SdJwt, SignatureAndEncryptionAlgorithm, Verifier } from "@sd-jwt/core";
import fs from 'fs';
import path from "path";
import { DataItem, DeviceSignedDocument, parse } from "@auth0/mdl";
import cbor from 'cbor-x';
import { verifyDeviceResponse } from "./lib/mdl/verify";
import config from "../../config";

const privateKeyJwk = JSON.parse(fs.readFileSync(path.join(__dirname, "../../../keys/service.private.jwk.json")).toString()) as JWK;


// https://identity.foundation/presentation-exchange/
// The fields object MAY contain a name property. If present, its value MUST be a string, and SHOULD be a human-friendly name that describes what the target field represents.
type CustomInputDescriptorConstraintFieldType = {
	name?: string;
	path: string[];
	filter?: any;
};

const hasherAndAlgorithm: HasherAndAlgorithm = {
	hasher: (input: string) => createHash('sha256').update(input).digest(),
	algorithm: HasherAlgorithm.Sha256
}

type VerifierState = {
	issuanceSessionID?: number;

	callbackEndpoint?: string;
	authorizationRequest?: AuthorizationRequestQueryParamsSchemaType;
	presentation_definition: PresentationDefinitionType;
	nonce: string;
	response_uri: string;
	client_id: string;
	signedRequestObject: string;
}

const verifierStates = new Map<string, VerifierState>();

const CLOCK_TOLERANCE = '15 minutes';

const nonces = new Map<string, string>(); // key: nonce, value: verifierStateId

const rootCert = fs.readFileSync(path.join(__dirname, '../../../keys/root.pem'), 'utf-8');


async function verifyCertificateChain(rootCert: string, pemCertChain: string[]) {
	const x509TrustAnchor = new X509Certificate(rootCert);
	const isLastCertTrusted = new X509Certificate(pemCertChain[pemCertChain.length - 1]).verify(x509TrustAnchor.publicKey);
	if (!isLastCertTrusted) {
		return false;
	}
	for (let i = 0; i < pemCertChain.length; i++) {
		if (pemCertChain[i + 1]) {
			const isTrustedCert = new X509Certificate(pemCertChain[i]).verify(new X509Certificate(pemCertChain[i + 1]).publicKey);
			if (!isTrustedCert) {
				return false;
			}
		}
	}
	return true;
}

function uint8ArrayToBase64Url(array: any) {
	// Convert the Uint8Array to a binary string
	let binaryString = '';
	array.forEach((byte: any) => {
		binaryString += String.fromCharCode(byte);
	});

	// Convert the binary string to a Base64 string
	let base64String = btoa(binaryString);

	// Convert the Base64 string to Base64URL format
	let base64UrlString = base64String
		.replace(/\+/g, '-') // Replace + with -
		.replace(/\//g, '_') // Replace / with _
		.replace(/=+$/, ''); // Remove trailing '='

	return base64UrlString;
}


@injectable()
export class OpenidForPresentationsReceivingService implements OpenidForPresentationsReceivingInterface {
	private verifiablePresentationRepository: Repository<VerifiablePresentationEntity> = AppDataSource.getRepository(VerifiablePresentationEntity);
	// private authorizationServerStateRepository: Repository<AuthorizationServerState> = AppDataSource.getRepository(AuthorizationServerState);

	constructor(
		@inject(TYPES.DidKeyResolverService) private didKeyResolverService: DidKeyResolverService,
		@inject(TYPES.VerifierConfigurationServiceInterface) private configurationService: VerifierConfigurationInterface,
	) { }



	metadataRequestHandler(_ctx: { req: Request, res: Response }): Promise<void> {
		throw new Error("Method not implemented.");
	}


	// @ts-ignore
	private async addIDtokenRequestSpecificAttributes(payload: any) {
		return payload;
	}

	public async getPresentationDefinitionHandler(ctx: { req: Request, res: Response }): Promise<void> {
		const state = ctx.req.query.state as string;
		if (state) {
			const verifierState = verifierStates.get(state);
			if (verifierState?.presentation_definition) {
				ctx.res.send(verifierState?.presentation_definition);
				return;
			}
		}
		ctx.res.status(404).send({ msg: "not found" });
	}


	public async getSignedRequestObject(ctx: { req: Request, res: Response }): Promise<any> {
		if (!ctx.req.query['id'] || typeof ctx.req.query['id'] != 'string') {
			return ctx.res.status(500).send({ error: "id does not exist on query params" });
		}
		const verifierStateId = ctx.req.query['id'] as string;
		const verifierState = verifierStates.get(verifierStateId);
		if (!verifierState) {
			return ctx.res.status(500).send({ error: "verifier state could not be fetched with this id" });
		}
		return ctx.res.send(verifierState.signedRequestObject);
	}


	async generateAuthorizationRequestURL(ctx: { req: Request, res: Response }, presentationDefinition: any, callbackEndpoint?: string): Promise<{ url: URL; stateId: string }> {
		const nonce = randomUUID();
		const stateId = randomUUID();
		nonces.set(nonce, stateId);

		console.log("Callback endpoint = ", callbackEndpoint)

		const responseUri = this.configurationService.getConfiguration().redirect_uri;
		const client_id = new URL(responseUri).hostname
		const privateKey = await importJWK(privateKeyJwk, 'ES256');
		const signedRequestObject = await new SignJWT({
			response_uri: responseUri,
			aud: "https://self-issued.me/v2",
			iss: new URL(responseUri).hostname,
			client_id_scheme: "x509_san_dns",
			client_id: client_id,
			response_type: "vp_token",
			response_mode: "direct_post",
			state: stateId,
			nonce: nonce,
			presentation_definition: presentationDefinition,
			client_metadata: {
				"vp_formats": {
					"mso_mdoc": {
						"alg": [
							"ES256",
						]
					},
					"vc+sd-jwt": {
						"sd-jwt_alg_values": [
							"ES256",
						],
						"kb-jwt_alg_values": [
							"ES256",
						]
					}
				}
			},
		})
			.setIssuedAt()
			.setProtectedHeader({
				alg: privateKeyJwk.alg as string,
				jwk: {
					kty: privateKeyJwk.kty,
					crv: privateKeyJwk.crv,
					x: privateKeyJwk.x,
					y: privateKeyJwk.y,
				}
			})
			.sign(privateKey);
		// try to get the redirect uri from the authorization server state in case this is a Dynamic User Authentication during OpenID4VCI authorization code flow
		const redirectUri = ctx.req?.authorizationServerState?.redirect_uri ?? "openid4vp://cb";

		verifierStates.set(stateId, { callbackEndpoint, nonce, response_uri: responseUri, client_id: client_id, signedRequestObject, presentation_definition: presentationDefinition });

		const requestUri = config.url + "/verification/request-object?id=" + stateId;

		const redirectParameters = {
			client_id: client_id,
			request_uri: requestUri
		};

		const searchParams = new URLSearchParams(redirectParameters);
		const authorizationRequestURL = new URL(redirectUri + "?" + searchParams.toString()); // must be openid4vp://cb
		return { url: authorizationRequestURL, stateId };
	}


	async responseHandler(ctx: { req: Request, res: Response }): Promise<{ verifierStateId: string, bindedUserSessionId?: number, vp_token?: string }> {
		console.log("Body = ", ctx.req.body)
		const { id_token, vp_token, state, presentation_submission } = ctx.req.body;
		console.log("Id token = ", id_token)
		// let presentationSubmissionObject: PresentationSubmission | null = qs.parse(decodeURI(presentation_submission)) as any;
		let presentationSubmissionObject: PresentationSubmission | null = presentation_submission ? JSON.parse(decodeURI(presentation_submission)) as any : null;

		console.log("Presentation submission object = ", presentationSubmissionObject)
		// if (presentation_submission) {
		// 	presentationSubmissionObject
		// }

		let verifierState = verifierStates.get(state);
		if (!verifierState) {
			throw new Error("Verifier state not found")
		}
		if (id_token) {
			const header = JSON.parse(base64url.decode(id_token.split('.')[0])) as { kid: string, alg: string };
			const jwk = await this.didKeyResolverService.getPublicKeyJwk(header.kid.split('#')[0]);
			const pubKey = await importJWK(jwk, header.alg as string);

			try {
				const { payload } = await jwtVerify(id_token, pubKey, {
					clockTolerance: CLOCK_TOLERANCE
					// audience: this.configurationService.getConfiguration().baseUrl,
				});
				const { nonce } = payload;
				// load verifier state by nonce
				if (!verifierState) {
					let verifierStateIdByNonce = nonces.get(nonce as string);
					if (!verifierStateIdByNonce) {
						const msg = { error: "EXPIRED_NONCE", error_description: "This nonce does not exist or has expired" };
						console.error(msg);
						const searchParams = new URLSearchParams(msg);
						ctx.res.redirect("/error" + '?' + searchParams);
						throw new Error("OpenID4VP Authorization Response failed. " + msg);
					}
					verifierState = verifierStates.get(verifierStateIdByNonce);
				}

				const state = verifierState?.authorizationRequest?.state;
				if (!verifierState) {
					const msg = { error: "ERROR_NONCE", error_description: "There is no verifier state with this 'nonce'" };
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect("/error" + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}

				if (payload.sub !== verifierState?.authorizationRequest?.client_id) {
					let msg = { error: "INVALID_SUB", error_description: "Subject of id_token should match authorizationRequest.client_id" };
					if (state) {
						msg = { ...msg, state } as any;
					}
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}

				if (payload.iss !== verifierState?.authorizationRequest?.client_id) {
					let msg = { error: "INVALID_ISS", error_description: "Issuer of id_token should match authorizationRequest.client_id" };
					if (state) {
						msg = { ...msg, state } as any;
					}
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}


				if (!nonce || typeof nonce != 'string') {
					let msg = { error: "ERROR_NONCE", error_description: "'nonce' does not exist or is not of type 'string" };
					if (state) {
						msg = { ...msg, state } as any;
					}
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}
				return { verifierStateId: state as string, bindedUserSessionId: verifierState.issuanceSessionID };
			}
			catch (e) {
				throw new Error("OpenID4VP Authorization Response failed. " + JSON.stringify(e));
			}

		}
		else if (vp_token) {

			try {


				console.log("Ver state = ", verifierState)
				// load verifier state by nonce

				if (presentationSubmissionObject?.descriptor_map[0].format != 'vc+sd-jwt' && presentationSubmissionObject?.descriptor_map[0].format != 'mso_mdoc') {
					throw new Error("Not supported format");
				}

				if (presentationSubmissionObject?.descriptor_map[0].format == 'vc+sd-jwt') {
					await (async function validateKbJwt() {
						const sdJwt = vp_token.split('~').slice(0, -1).join('~') + '~';
						const kbJwt = vp_token.split('~')[vp_token.split('~').length - 1] as string;
						const { sd_hash, nonce, aud } = JSON.parse(base64url.decode(kbJwt.split('.')[1])) as any;
						async function calculateHash(text: string) {
							const encoder = new TextEncoder();
							const data = encoder.encode(text);
							const hashBuffer = await crypto.subtle.digest('SHA-256', data);
							const base64String = btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
							const base64UrlString = base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
							return base64UrlString;
						}
						if (await calculateHash(sdJwt) != sd_hash) {
							throw new Error("Wrong sd_hash");
						}
						if (aud != verifierState.client_id) {
							throw new Error("Wrong aud");
						}
						let verifierStateIdByNonce = nonces.get(nonce as string);
						if (!verifierStateIdByNonce) {
							throw new Error("Invalid nonce");
						}
						return { sdJwt };
					})();
				}

				console.log("VP token = ", vp_token)
				if (!verifierState) {
					const msg = { error: "ERROR_NONCE", error_description: "There is no verifier state with this 'nonce'" };
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect("/error" + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}

				// perform verification of vp_token
				let msg = {};
				if (state) {
					msg = { ...msg, state } as any;
				}
				const { presentationClaims, error, error_description } = await this.validateVpToken(vp_token, presentationSubmissionObject as PresentationSubmission, verifierState);
				if (error && error_description) {
					msg = { ...msg, error: error.message, error_description: error_description?.message };
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
					throw new Error(error.message + "\n" + error_description?.message);
				}

				// store presentation
				const newVerifiablePresentation = new VerifiablePresentationEntity()
				newVerifiablePresentation.presentation_definition_id = (JSON.parse(presentation_submission) as any).definition_id;
				newVerifiablePresentation.claims = presentationClaims ?? null;
				newVerifiablePresentation.status = true;
				newVerifiablePresentation.raw_presentation = vp_token;
				newVerifiablePresentation.presentation_submission = presentationSubmissionObject;
				newVerifiablePresentation.date = new Date();
				newVerifiablePresentation.state = state as string;
				await this.verifiablePresentationRepository.save(newVerifiablePresentation);

				console.error(msg);
				//@ts-ignore
				const searchParams = new URLSearchParams(msg);

				// if not in issuance flow, then redirect to complete the verification flow
				if (!verifierState.issuanceSessionID) {
					// ctx.res.send("OK")
					console.log("FINISHED")
					ctx.res.send({ redirect_uri: verifierState.callbackEndpoint + '?' + searchParams })
					// ctx.res.redirect(verifierState.callbackEndpoint + '?' + searchParams);
				}

			}
			catch (e) {
				console.error(e)
				throw new Error("OpenID4VP Authorization Response failed. " + JSON.stringify(e));
			}
		}
		throw new Error("OpenID4VP Authorization Response failed. Path not implemented");
	}

	private async validateVpToken(vp_token: string, presentation_submission: PresentationSubmission, verifierState: VerifierState): Promise<{ presentationClaims?: PresentationClaims, error?: Error, error_description?: Error }> {
		let presentationClaims: PresentationClaims = {};



		for (const desc of presentation_submission.descriptor_map) {
			if (!presentationClaims[desc.id]) {
				presentationClaims[desc.id] = [];
			}


			if (desc.format == VerifiableCredentialFormat.VC_SD_JWT) {
				const sdJwt = vp_token.split('~').slice(0, -1).join('~') + '~';
				const kbJwt = vp_token.split('~')[vp_token.split('~').length - 1] as string;
				const path = desc?.path as string;
				console.log("Path = ", path)

				const input_descriptor = verifierState!.presentation_definition!.input_descriptors.filter((input_desc: any) => input_desc.id == desc.id)[0];
				if (!input_descriptor) {
					return { error: new Error("Input descriptor not found") };
				}
				const requiredClaimNames = input_descriptor.constraints.fields.map((field: any) => {
					const fieldPath = field.path[0];
					const splittedPath = fieldPath.split('.');
					return splittedPath[splittedPath.length - 1]; // return last part of the path
				});

				const parsedSdJwt = SdJwt.fromCompact(sdJwt).withHasher(hasherAndAlgorithm);

				const jwtPayload = (JSON.parse(base64url.decode(sdJwt.split('.')[1])) as any);

				// kbjwt validation
				try {
					const { alg } = JSON.parse(base64url.decode(kbJwt.split('.')[0])) as { alg: string }; 
					const publicKey = await importJWK(jwtPayload.cnf.jwk, alg);
					await jwtVerify(kbJwt, publicKey);
				}
				catch(err) {
					return { error: new Error("PRESENTATION_RESPONSE:INVALID_KB_JWT"), error_description: new Error("KB JWT validation failed") };
				}

				const issuerDID = jwtPayload.iss;


				const verifyCb: Verifier = async ({ header, message, signature }) => {
					if (header.alg !== SignatureAndEncryptionAlgorithm.ES256) {
						throw new Error('only ES256 is supported')
					}
					if (header['x5c'] && header['x5c'] instanceof Array && header['x5c'][0]) {
						const pemCerts = header['x5c'].map(cert => {
							const pemCert = `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----`;
							return pemCert;
						});

						const chainIsTrusted = await verifyCertificateChain(rootCert, pemCerts);
						if (!chainIsTrusted) {
							console.log("Chain is not trusted");
							return false;
						}
						const cert = await importX509(pemCerts[0], 'ES256');
						return jwtVerify(message + '.' + uint8ArrayToBase64Url(signature), cert).then(() => true).catch((err: any) => {
							console.log("Error verifying")
							console.error(err);
							return false;
						});
					}
					const issuerPublicKeyJwk = await this.didKeyResolverService.getPublicKeyJwk(issuerDID);
					const alg = (JSON.parse(base64url.decode(sdJwt.split('.')[0])) as any).alg;
					const issuerPublicKey = await importJWK(issuerPublicKeyJwk, alg);

					return verify(null, Buffer.from(message), issuerPublicKey as KeyLike, signature)
				}

				const verificationResult = await parsedSdJwt.verify(verifyCb, requiredClaimNames);
				const prettyClaims = await parsedSdJwt.getPrettyClaims();

				input_descriptor.constraints.fields.map((field: any) => {
					if (!presentationClaims[desc.id]) {
						presentationClaims[desc.id] = []; // initialize
					}
					const fieldPath = field.path[0]; // get first path
					const fieldName = (field as CustomInputDescriptorConstraintFieldType).name;
					const value = String(JSONPath({ path: fieldPath, json: prettyClaims.vc as any ?? prettyClaims })[0]);
					const splittedPath = fieldPath.split('.');
					const claimName = fieldName ? fieldName : splittedPath[splittedPath.length - 1];
					presentationClaims[desc.id].push({ name: claimName, value: typeof value == 'object' ? JSON.stringify(value) : value } as ClaimRecord);
				});
				console.log("Verification result = ", verificationResult)
				if (!verificationResult.isSignatureValid || !verificationResult.areRequiredClaimsIncluded) {
					return { error: new Error("SD_JWT_VERIFICATION_FAILURE"), error_description: new Error(`Verification result ${JSON.stringify(verificationResult)}`) };
				}
			}
			else if (desc.format == VerifiableCredentialFormat.MSO_MDOC) {
				const definition = this.configurationService.getPresentationDefinitions().filter((pd) => pd.id == presentation_submission.definition_id)[0]
				console.log("Credential to be mdoc parsed = ", vp_token)
				const b = Buffer.from(vp_token, 'base64url');
				const parsed = parse(b);
				const ns = parsed.documents[0].getIssuerNameSpace(parsed.documents[0].issuerSignedNameSpaces[0]);
				const json: any = {};
				json[parsed.documents[0].docType] = ns;

				// TODO: read verifier generated nonce from payload of device signature part
				const [document] = parsed.documents as DeviceSignedDocument[];
				const p: DataItem = cbor.decode(document.deviceSigned.deviceAuth.deviceSignature!.payload);

				const [_devAuth, [_deviceEngagementBytes, _eReaderKeyBytes, [mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce]]] = p.data;

				// verify that the session transcript is matching with the verifier session data (nonce, client_id, repsonse_uri)
				console.log("Device signature payload containts = ", [mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce]);
				if (verifierGeneratedNonce !== verifierState.nonce) { // check nonce
					return { error: new Error("PRESENTATION_RESPONSE:INVALID_NONCE"), error_description: new Error("Invalid nonce") };
				}

				if (responseUri !== verifierState.response_uri) {
					return { error: new Error("PRESENTATION_RESPONSE:INVALID_RESPONSE_URI"), error_description: new Error("Invalid response_uri") };
				}

				if (clientId !== verifierState.client_id) {
					return { error: new Error("PRESENTATION_RESPONSE:INVALID_CLIENT_ID"), error_description: new Error("Invalid client_id") };
				}

				const verificationResult = await verifyDeviceResponse(Buffer.from(vp_token, 'base64url'), [rootCert], verifierState.client_id, verifierState.response_uri, verifierState.nonce, mdocGeneratedNonce)

				if (!verificationResult) {
					console.log("Failed to verify the mdoc credential");
					return { error: new Error("PRESENTATION_RESPONSE:MDOC_VERIFICATION_FAILED"), error_description: new Error("Failed to verify the mdoc credential") };
				}
				const fieldNamesWithValues = definition.input_descriptors[0].constraints.fields.map((field) => {
					const values = field.path.map((possiblePath) => JSONPath({ path: possiblePath, json: json })[0]);
					const val = values.filter((v) => v != undefined || v != null)[0]; // get first value that is not undefined
					return val ? { name: (field as CustomInputDescriptorConstraintFieldType).name as string, value: typeof val == 'object' ? JSON.stringify(val) : val as string } : undefined;
				});

				if (fieldNamesWithValues.includes(undefined)) {
					return { error: new Error("INSUFFICIENT_CREDENTIALS"), error_description: new Error("Insufficient credentials") };
				}

				for (const { name, value } of fieldNamesWithValues as { name: string, value: string }[]) {
					presentationClaims[desc.id].push({ name, value });
				}

			}
		}

		console.log("presentation claims = ", presentationClaims)
		return { presentationClaims };
	}

	//@ts-ignore
	private async isExpired(vcjwt: string): Promise<boolean> {
		const payload = JSON.parse(base64url.decode(vcjwt.split('.')[1])) as { exp: number };
		return payload.exp ? payload.exp < Math.floor(Date.now() / 1000) : false;
	}

	//@ts-ignore
	// private async isNotValidYet(vcjwt: string): Promise<boolean> {
	// 	const payload = JSON.parse(base64url.decode(vcjwt.split('.')[1])) as { nbf: number };
	// 	return payload.nbf ? payload.nbf > Math.floor(Date.now() / 1000) : false;
	// }

	//@ts-ignore
	private async isRevoked(_vcjwt: string): Promise<boolean> {
		return false;
	}




	async sendAuthorizationResponse(ctx: { req: Request, res: Response }, verifierStateId: string): Promise<void> {
		const verifierState = verifierStates.get(verifierStateId);
		const state = verifierState?.authorizationRequest?.state;
		const code = randomUUID();
		let msg: any = { code };
		if (state)
			msg = { ...msg, state };

		const searchParams = new URLSearchParams(msg);
		ctx.res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
	}


	public async getPresentationByState(state: string): Promise<{ status: true, vp: VerifiablePresentationEntity } | { status: false }> {
		const vp = await this.verifiablePresentationRepository.createQueryBuilder('vp')
			.where("state = :state", { state: state })
			.getOne();

		if (!vp?.raw_presentation || !vp.claims) {
			return { status: false };
		}

		if (vp)
			return { status: true, vp };
		else
			return { status: false };
	}

	public async getPresentationById(id: string): Promise<{ status: boolean, presentationClaims?: PresentationClaims, rawPresentation?: string }> {
		const vp = await this.verifiablePresentationRepository.createQueryBuilder('vp')
			.where("id = :id", { id: id })
			.getOne();

		if (!vp?.raw_presentation || !vp.claims) {
			return { status: false };
		}

		if (vp)
			return { status: true, presentationClaims: vp.claims, rawPresentation: vp?.raw_presentation };
		else
			return { status: false };
	}
}