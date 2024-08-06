import { inject, injectable } from "inversify";
import { Request, Response } from 'express'
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "./interfaces";
import { VerifiableCredentialFormat } from "../types/oid4vci";
import { AuthorizationRequestQueryParamsSchemaType } from "../types/oid4vci";
import { TYPES } from "./types";
import { importJWK, importX509, jwtVerify } from "jose";
import { KeyLike, createHash, randomUUID, verify, X509Certificate } from "crypto";
import base64url from "base64url";
import { PresentationDefinitionType, PresentationSubmission } from "@wwwallet/ssi-sdk";
import 'reflect-metadata';
import { JSONPath } from "jsonpath-plus";
import { Repository } from "typeorm";
import { ClaimRecord, PresentationClaims, VerifiablePresentationEntity } from "../entities/VerifiablePresentation.entity";
import AppDataSource from "../AppDataSource";
import config from "../../config";
import { DidKeyResolverService } from "./DidKeyResolverService";
import { HasherAlgorithm, HasherAndAlgorithm, SdJwt, SignatureAndEncryptionAlgorithm, Verifier } from "@sd-jwt/core";
import fs from 'fs';
import path from "path";
import { DataItem, DeviceSignedDocument, parse } from "@auth0/mdl";
import cbor from 'cbor-x';
import { verifyDeviceResponse } from "./lib/mdl/verify";

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
	callbackEndpoint?: string;
	authorizationRequest?: AuthorizationRequestQueryParamsSchemaType;
	issuanceSessionID?: number;
	presentation_definition?: PresentationDefinitionType;
	nonce: string;
	response_uri: string;
	client_id: string;
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

	private async addVPtokenRequestSpecificAttributes(verifierStateId: string, payload: any, presentationDefinition: object) {
		const verifierState = verifierStates.get(verifierStateId);
		if (verifierState) {
			verifierStates.set(verifierStateId, { ...verifierState, presentation_definition: presentationDefinition as any })
			payload = { ...payload, presentation_definition_uri: config.url + '/verification/definition?state=' + payload.state };
			return payload;
		}
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


	async generateAuthorizationRequestURL(ctx: { req: Request, res: Response }, presentationDefinition: object, callbackEndpoint?: string): Promise<{ url: URL; stateId: string }> {
		const nonce = randomUUID();
		const stateId = randomUUID();
		nonces.set(nonce, stateId);
		let payload = {
			client_id: this.configurationService.getConfiguration().client_id,
			client_id_scheme: "redirect_uri",
			response_type: "vp_token",
			response_mode: "direct_post",
			response_uri: this.configurationService.getConfiguration().redirect_uri,
			scope: "openid",
			nonce: nonce,
			state: stateId,
		};

		// try to get the redirect uri from the authorization server state in case this is a Dynamic User Authentication during OpenID4VCI authorization code flow
		const redirectUri = ctx.req?.authorizationServerState?.redirect_uri ?? "openid://cb";

		verifierStates.set(stateId, { callbackEndpoint, nonce, response_uri: payload.response_uri, client_id: payload.client_id });
		payload = await this.addVPtokenRequestSpecificAttributes(stateId, payload, presentationDefinition);
		console.log("Payload = ", payload)
		// const requestJwt = new SignJWT(payload)
		// 	.setExpirationTime('30s');

		// const { jws } = await this.walletKeystoreService.signJwt(
		// 	this.configurationService.getConfiguration().authorizationServerWalletIdentifier,
		// 	requestJwt,
		// 	"JWT"
		// );

		// const requestJwtSigned = jws;
		const redirectParameters = {
			...payload,
			state: stateId,
			// request: requestJwtSigned,
		};

		const searchParams = new URLSearchParams(redirectParameters);
		const authorizationRequestURL = new URL(redirectUri + "?" + searchParams.toString()); // must be openid://cb
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

		let verifierStateId = null;
		let verifierState = null;
		if (state) {
			verifierState = verifierStates.get(state)
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
				if (!verifierState) {
					const payload = JSON.parse(base64url.decode(vp_token.split('.')[1])) as any;

					const { nonce } = payload;
					let verifierStateIdByNonce = nonces.get(nonce as string);
					verifierStateId = verifierStateIdByNonce;
					if (!verifierStateIdByNonce) {
						const msg = { error: "EXPIRED_NONCE", error_description: "This nonce does not exist or has expired" };
						console.error(msg);
						const searchParams = new URLSearchParams(msg);
						ctx.res.redirect("/error" + '?' + searchParams);
						throw new Error("OpenID4VP Authorization Response failed. " + msg);
					}
					verifierState = verifierStates.get(verifierStateIdByNonce);
				}

				if (!verifierState) {
					const msg = { error: "ERROR_NONCE", error_description: "There is no verifier state with this 'nonce'" };
					console.error(msg);
					const searchParams = new URLSearchParams(msg);
					ctx.res.redirect("/error" + '?' + searchParams);
					throw new Error("OpenID4VP Authorization Response failed. " + msg);
				}

				// if (payload.sub !== verifierState?.authorizationRequest?.client_id) {
				// 	let msg = { error: "INVALID_SUB", error_description: "Subject of vp_token should match authorizationRequest.client_id" };
				// 	if (state) {
				// 		msg = { ...msg, state } as any;
				// 	}
				// 	console.error(msg);
				// 	const searchParams = new URLSearchParams(msg);
				// 	res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
				// 	throw new Error("OpenID4VP Authorization Response failed." + msg);
				// }

				// if (payload.iss !== verifierState?.authorizationRequest?.client_id) {
				// 	let msg = { error: "INVALID_ISS", error_description: "Issuer of vp_token should match authorizationRequest.client_id" };
				// 	if (state) {
				// 		msg = { ...msg, state } as any;
				// 	}
				// 	console.error(msg);
				// 	const searchParams = new URLSearchParams(msg);
				// 	res.redirect(verifierState?.authorizationRequest?.redirect_uri + '?' + searchParams);
				// 	throw new Error("OpenID4VP Authorization Response failed. " + msg);
				// }

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

				console.log("binding issuanc sesssion id = ", verifierState.issuanceSessionID)
				return { verifierStateId: verifierStateId as string, bindedUserSessionId: verifierState.issuanceSessionID };
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

		let payload: any;

		if (presentation_submission.descriptor_map[0].format == VerifiableCredentialFormat.MSO_MDOC) {
			payload = null;
		}
		else {
			payload = JSON.parse(base64url.decode(vp_token.split('.')[1])) as { nonce: string, vp: { verifiableCredential: string[] } };
			if (!payload.nonce || payload.nonce !== verifierState.nonce) {
				return { error: new Error("PRESENTATION_RESPONSE:INVALID_NONCE" ), error_description: new Error("Invalid nonce") };
			}
		}




		for (const desc of presentation_submission.descriptor_map) {
			if (!presentationClaims[desc.id]) {
				presentationClaims[desc.id] = [];
			}


			if (desc.format == VerifiableCredentialFormat.VC_SD_JWT) {
				const path = desc?.path as string;
				console.log("Path = ", path)
				let verifiableCredential = JSONPath({ json: payload.vp, path: path })[0];
				console.log("Verifiable credential = ", verifiableCredential)
				if (verifiableCredential.length == 0) {
					return { error: new Error("VC_NOT_FOUND"), error_description: new Error(`Path on descriptor ${desc.id} not matching to a credential`) };
				}
				const input_descriptor = verifierState!.presentation_definition!.input_descriptors.filter((input_desc: any) => input_desc.id == desc.id)[0];
				if (!input_descriptor) {
					return { error: new Error("Input descriptor not found") };
				}
				const requiredClaimNames = input_descriptor.constraints.fields.map((field: any) => {
					const fieldPath = field.path[0];
					const splittedPath = fieldPath.split('.');
					return splittedPath[splittedPath.length - 1]; // return last part of the path
				});

				const sdJwt = SdJwt.fromCompact(verifiableCredential).withHasher(hasherAndAlgorithm);

				const jwtPayload = (JSON.parse(base64url.decode(verifiableCredential.split('.')[1])) as any);
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
					const alg = (JSON.parse(base64url.decode(verifiableCredential.split('.')[0])) as any).alg;
					const issuerPublicKey = await importJWK(issuerPublicKeyJwk, alg);

					return verify(null, Buffer.from(message), issuerPublicKey as KeyLike, signature)
				}

				const verificationResult = await sdJwt.verify(verifyCb, requiredClaimNames);
				const prettyClaims = await sdJwt.getPrettyClaims();

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
			else if (desc.format == VerifiableCredentialFormat.JWT_VC) {
				const path = desc?.path as string;
				console.log("Path = ", path)
				let verifiableCredential = JSONPath({ json: payload.vp, path: path })[0];
				console.log("Verifiable credential = ", verifiableCredential)
				if (verifiableCredential.length == 0) {
					return { error: new Error("VC_NOT_FOUND"), error_description: new Error(`Path on descriptor ${desc.id} not matching to a credential`) };
				}
				const input_descriptor = verifierState!.presentation_definition!.input_descriptors.filter((input_desc: any) => input_desc.id == desc.id)[0];
				if (!input_descriptor) {
					return { error: new Error("Input descriptor not found") };
				}
				const jwtPayload = (JSON.parse(base64url.decode(verifiableCredential.split('.')[1])) as any);
				const issuerDID = jwtPayload.iss;
				const issuerPublicKeyJwk = await this.didKeyResolverService.getPublicKeyJwk(issuerDID);
				const alg = (JSON.parse(base64url.decode(verifiableCredential.split('.')[0])) as any).alg;
				const issuerPublicKey = await importJWK(issuerPublicKeyJwk, alg);

				await jwtVerify(verifiableCredential, issuerPublicKey);

				input_descriptor.constraints.fields.map((field: any) => {
					if (!presentationClaims[desc.id]) {
						presentationClaims[desc.id] = []; // initialize
					}
					const fieldPath = field.path[0]; // get first path
					const fieldName = (field as CustomInputDescriptorConstraintFieldType).name;
					const value = String(JSONPath({ path: fieldPath, json: jwtPayload.vc })[0]);
					const splittedPath = fieldPath.split('.');
					const claimName = fieldName ? fieldName : splittedPath;
					presentationClaims[desc.id].push({ name: claimName, value: typeof value == 'object' ? JSON.stringify(value) : value } as ClaimRecord);
				});
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
				const [ document ] = parsed.documents as DeviceSignedDocument[];
				const p: DataItem = cbor.decode(document.deviceSigned.deviceAuth.deviceSignature!.payload);

				const [_devAuth, [_deviceEngagementBytes, _eReaderKeyBytes, [mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce]]] = p.data;

				// verify that the session transcript is matching with the verifier session data (nonce, client_id, repsonse_uri)
				console.log("Device signature payload containts = ", [mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce]);
				if (verifierGeneratedNonce !== verifierState.nonce) { // check nonce
					return { error: new Error("PRESENTATION_RESPONSE:INVALID_NONCE" ), error_description: new Error("Invalid nonce") };
				}

				if (responseUri !== verifierState.response_uri) {
					return { error: new Error("PRESENTATION_RESPONSE:INVALID_RESPONSE_URI" ), error_description: new Error("Invalid response_uri") };
				}

				if (clientId !== verifierState.client_id) {
					return { error: new Error("PRESENTATION_RESPONSE:INVALID_CLIENT_ID" ), error_description: new Error("Invalid client_id") };
				}
				
				const verificationResult = await verifyDeviceResponse(Buffer.from(vp_token, 'base64url'), [ rootCert ], verifierState.client_id, verifierState.response_uri, verifierState.nonce, mdocGeneratedNonce)

				if (!verificationResult) {
					console.log("Failed to verify the mdoc credential");
					return  { error: new Error("PRESENTATION_RESPONSE:MDOC_VERIFICATION_FAILED"), error_description: new Error("Failed to verify the mdoc credential") };
				}
				const fieldNamesWithValues = definition.input_descriptors[0].constraints.fields.map((field) => {
					const values = field.path.map((possiblePath) => JSONPath({ path: possiblePath, json: json })[0]);
					const val = values.filter((v) => v != undefined || v != null)[0]; // get first value that is not undefined
					return val ? { name: (field as CustomInputDescriptorConstraintFieldType).name as string, value: typeof val == 'object' ? JSON.stringify(val) : val as string } : undefined;
				});

				if (fieldNamesWithValues.includes(undefined)) {
					return { error: new Error("INSUFFICIENT_CREDENTIALS"), error_description: new Error("Insufficient credentials") };
				}

				for (const { name, value } of fieldNamesWithValues as {name: string, value: string }[]) {
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