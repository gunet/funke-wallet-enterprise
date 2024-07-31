import { Router } from "express";
import { verifierPanelAuthChain } from "../configuration/authentication/authenticationChain";
import { Repository } from "typeorm";
import AppDataSource from "../AppDataSource";
import { VerifiablePresentationEntity } from "../entities/VerifiablePresentation.entity";
import { appContainer } from "../services/inversify.config";
import { TYPES } from "../services/types";
import { OpenidForPresentationsReceivingInterface, VerifierConfigurationInterface } from "../services/interfaces";
import base64url from "base64url";
import locale from "../configuration/locale";
import crypto from 'node:crypto';

import {
	HasherAndAlgorithm,
	HasherAlgorithm,
	SdJwt,
} from '@sd-jwt/core'


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


const openidForPresentationReceivingService = appContainer.get<OpenidForPresentationsReceivingInterface>(TYPES.OpenidForPresentationsReceivingService);


const verifierPanelRouter = Router();
const verifiablePresentationRepository: Repository<VerifiablePresentationEntity> = AppDataSource.getRepository(VerifiablePresentationEntity);
const verifierConfiguration = appContainer.get<VerifierConfigurationInterface>(TYPES.VerifierConfigurationServiceInterface);


verifierPanelAuthChain.components.map(c => {
	verifierPanelRouter.use(async (req, res, next) => {
		c.authenticate(req, res, next)
	});
})


verifierPanelRouter.get('/', async (req, res) => {
	
	return res.render('verifier/definitions.pug', {
		lang: req.lang,
		presentationDefinitions: verifierConfiguration.getPresentationDefinitions(),
		locale: locale[req.lang]
	})
})

type VerifiablePresentationWithDetails = VerifiablePresentationEntity & { holderInfo?: string, claims?: any };

verifierPanelRouter.get('/filter/by/definition/:definition_id', async (req, res) => {
	const definition_id = req.params.definition_id;
	if (!definition_id) {
		return res.status(500).send({ error: "No definition id was specified" });
	}
	let verifiablePresentations = await verifiablePresentationRepository.createQueryBuilder('vp')
		.where("vp.presentation_definition_id = :definition_id", { definition_id: definition_id })
		.getMany();

	const presentationsWithDetails: VerifiablePresentationWithDetails[] = verifiablePresentations.map(vp => {
		try {
			const decoded = vp.raw_presentation ? JSON.parse(base64url.decode(vp.raw_presentation.split('.')[1])) : null as any;
			const holderInfo = decoded?.vp?.holder || "No Holder Info";
			const claims = vp.claims;
			return { ...vp, holderInfo, claims } as VerifiablePresentationWithDetails;
		} catch (error) {
			console.error("Error decoding VP:", error);
			return { ...vp, holderInfo: 'Error decoding holder info' } as VerifiablePresentationWithDetails;
		}
	});

	return res.render('verifier/presentations.pug', {
		lang: req.lang,
		verifiablePresentations: presentationsWithDetails,
		locale: locale[req.lang]
	})
})


verifierPanelRouter.get('/presentation/:presentation_id', async (req, res) => {
	const presentation_id = req.params.presentation_id;
	if (!presentation_id) {
		return res.status(500).send({ error: "No presentation_id was specified" });
	}
	const { presentationClaims, rawPresentation } = await openidForPresentationReceivingService.getPresentationById(presentation_id as string);

	if (!presentationClaims || !rawPresentation) {
		return res.render('error.pug', {
			msg: "Failed to get presentation",
			code: 0,
			lang: req.lang,
			locale: locale[req.lang],
		})
	}

	const presentationPayload = JSON.parse(base64url.decode(rawPresentation.split('.')[1])) as any;
	const credentials = await Promise.all(presentationPayload.vp.verifiableCredential.map(async (vcString: any) => {
		if (vcString.includes('~')) {
			return SdJwt.fromCompact<Record<string, unknown>, any>(vcString)
				.withHasher(hasherAndAlgorithm)
				.getPrettyClaims()
				.then((payload) => payload.vc ?? payload);
		}
		else {
			return JSON.parse(base64url.decode(vcString.split('.')[1]));
		}
	}));

	return res.render('verifier/detailed-presentation.pug', {
		lang: req.lang,
		presentationClaims: presentationClaims,
		credentialPayloads: credentials,
		locale: locale[req.lang],
	})
})

export { verifierPanelRouter };