import { Router } from "express";
// import { Repository } from "typeorm";
// import { VerifiablePresentationEntity } from "../entities/VerifiablePresentation.entity";
// import AppDataSource from "../AppDataSource";
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "../services/interfaces";
import { appContainer } from "../services/inversify.config";
import { TYPES } from "../services/types";
import locale from "../configuration/locale";
import * as qrcode from 'qrcode';
import config from "../../config";
import { PresentationDefinitionTypeWithFormat } from "../configuration/verifier/VerifierConfigurationService";
import crypto from 'node:crypto';
import {
	HasherAlgorithm,
	HasherAndAlgorithm,
	SdJwt,
} from '@sd-jwt/core'
import { VerifiableCredentialFormat } from "../types/oid4vci";
import { parse } from "@auth0/mdl";

export enum CredentialFormat {
	VC_SD_JWT = "vc+sd-jwt",
	JWT_VC_JSON = "jwt_vc_json"
}

// const encoder = new TextEncoder();

// Encoding the string into a Uint8Array
const hasherAndAlgorithm: HasherAndAlgorithm = {
	hasher: (input: string) => {
		// return crypto.subtle.digest('SHA-256', encoder.encode(input)).then((v) => new Uint8Array(v));
		return new Promise((resolve, _reject) => {
			const hash = crypto.createHash('sha256');
			hash.update(input);
			resolve(new Uint8Array(hash.digest()));
	});
	},
	algorithm: HasherAlgorithm.Sha256
}

const verifierRouter = Router();
// const verifiablePresentationRepository: Repository<VerifiablePresentationEntity> = AppDataSource.getRepository(VerifiablePresentationEntity);
const verifierConfiguration = appContainer.get<VerifierConfigurationInterface>(TYPES.VerifierConfigurationServiceInterface);
const openidForPresentationReceivingService = appContainer.get<OpenidForPresentationsReceivingInterface>(TYPES.OpenidForPresentationsReceivingService);

verifierRouter.get('/public/definitions', async (req, res) => {
	
	return res.render('verifier/public_definitions.pug', {
		lang: req.lang,
		presentationDefinitions: verifierConfiguration.getPresentationDefinitions(),
		locale: locale[req.lang]
	})
})


verifierRouter.get('/success/status', async (req, res) => { // response with the status of the presentation (this endpoint should be protected)
	const state = req.query.state;
	const result = await openidForPresentationReceivingService.getPresentationByState(state as string);
	if (!result.status) {
		return res.send({ status: false, error: "Presentation not received" });
	}
	return res.send({ status: result.status, presentationClaims: result.vp.claims, presentation: result.vp.raw_presentation });
})

verifierRouter.get('/success', async (req, res) => {
	const state = req.query.state;
	const result = await openidForPresentationReceivingService.getPresentationByState(state as string);
	console.log("Presentation by state = ", result)
	if (result.status == false || 
			result.vp.raw_presentation == null ||
			result.vp.claims == null ||
			result.vp.date == null) {
		return res.render('error.pug', {
			msg: "Failed to get presentation",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang],
		})
	}
	
	const { status, raw_presentation, claims, date, presentation_submission } = result.vp;

	let credentials: any[] = [];
	if (presentation_submission.descriptor_map[0].format == VerifiableCredentialFormat.MSO_MDOC) {
		const mdoc = parse(Buffer.from(raw_presentation, 'base64url'));
		const [document] = mdoc.documents;
	
		// decode the namespaces and add them to the document
		// @ts-ignore
		document.issuerSigned.nameSpaces[presentation_submission.descriptor_map[0].id] = document.getIssuerNameSpace(presentation_submission.descriptor_map[0].id);
		credentials = [ document ];
	}
	else if (presentation_submission.descriptor_map[0].format == VerifiableCredentialFormat.VC_SD_JWT) {
		credentials = [
			await SdJwt.fromCompact<Record<string, unknown>, any>(raw_presentation)
				.withHasher(hasherAndAlgorithm)
				.getPrettyClaims()
				.then((payload: any) => payload.vc ?? payload)
		]
	}
	


	return res.render('verifier/success.pug', {
		lang: req.lang,
		locale: locale[req.lang],
		status: status,
		verificationTimestamp: date.toISOString(),
		presentationClaims: claims,
		credentialPayloads: credentials,
	})
})


verifierRouter.use('/public/definitions/selectable-presentation-request/:presentation_definition_id', async (req, res) => {
	const presentation_definition_id = req.params.presentation_definition_id;
	if (!presentation_definition_id) {
		return res.render('error', {
			msg: "No presentation definition was selected",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang]
		});
	}
	const presentationDefinition = verifierConfiguration.getPresentationDefinitions().filter(pd => pd.id == presentation_definition_id)[0];
	if (!presentationDefinition) {
		return res.render('error', {
			msg: "No presentation definition was found",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang]
		});
	}
	return res.render('verifier/selectable_presentation', {
		presentationDefinitionId: presentationDefinition.id,
		lang: req.lang,
		locale: locale[req.lang],
	});
})


verifierRouter.use('/public/definitions/presentation-request/:presentation_definition_id', async (req, res) => {
	const presentation_definition_id = req.params.presentation_definition_id;
	if (req.body.state && req.method == "POST") {
		const { status } = await openidForPresentationReceivingService.getPresentationByState(req.body.state as string);
		if (status) {
			return res.send({ url: `/verifier/success?state=${req.body.state}` });
		}
		else {
			return res.send({ });
		}
	}

	if (!presentation_definition_id) {
		return res.render('error', {
			msg: "No presentation definition was selected",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang]
		});
	}

	const presentationDefinition = JSON.parse(JSON.stringify(verifierConfiguration.getPresentationDefinitions().filter(pd => pd.id == presentation_definition_id)[0])) as PresentationDefinitionTypeWithFormat;
	if (!presentationDefinition) {
		return res.render('error', {
			msg: "No presentation definition was found",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang]
		});
	}

	// If there are selected fields from a POST request, update the constraints accordingly
	if (req.method === "POST" && req.body.fields) {
		let selectedFields = req.body.fields;
		if (!Array.isArray(selectedFields)) {
			selectedFields = [selectedFields];
		}
		const selectedPaths = new Set(selectedFields.map((field: string) => {
				return `$.${field}`;
		}));
		// Filter existing paths to keep only those selected by the user and update presentationDefinition
		const availableFields = presentationDefinition.input_descriptors[0].constraints.fields;
		console.log("Available fields = ", availableFields)
		const filteredFields = presentationDefinition.input_descriptors[0].constraints.fields.filter(field =>
			selectedPaths.has(field.path[0])
		);

		console.log("filtered fields = ", filteredFields)
		presentationDefinition.input_descriptors[0].constraints.fields = filteredFields;
	}

	const { url, stateId } = await openidForPresentationReceivingService.generateAuthorizationRequestURL({req, res}, presentationDefinition, config.url + "/verifier/success");	
	let authorizationRequestQR = await new Promise((resolve) => {
		qrcode.toDataURL(url.toString(), {
			margin: 1,
			errorCorrectionLevel: 'L',
			type: 'image/png'
		}, 
		(err, data) => {
			if (err) return resolve("NO_QR");
			return resolve(data);
		});
	}) as string;

	console.log("URL = ", url)
	return res.render('verifier/QR.pug', {
		wwwalletURL: config.wwwalletURL,
		authorizationRequestURL: url.toString(),
		authorizationRequestQR,
		state: stateId,
		lang: req.lang,
		locale: locale[req.lang],
	})
})


export { verifierRouter };