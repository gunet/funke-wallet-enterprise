import { Application } from 'express';
import { inject, injectable } from 'inversify';
import 'reflect-metadata';
import { TYPES } from './types';
import { OpenidForCredentialIssuingAuthorizationServerInterface } from './interfaces';
import { OpenidForPresentationsReceivingService } from './OpenidForPresentationReceivingService';
import { CredentialIssuersService } from './CredentialIssuersService';
import { ApplicationModeType, applicationMode } from '../configuration/applicationMode';

@injectable()
export class ExpressAppService {

	


	constructor(
		@inject(TYPES.OpenidForCredentialIssuingAuthorizationServerService) private authorizationServerService: OpenidForCredentialIssuingAuthorizationServerInterface,
		@inject(TYPES.OpenidForPresentationsReceivingService) private presentationsReceivingService: OpenidForPresentationsReceivingService,
		@inject(TYPES.CredentialIssuersService) private credentialIssuersService: CredentialIssuersService
	) { }


	public configure(app: Application) {
		// exposed in any mode
		app.post('/verification/direct_post', this.directPostEndpoint());
		app.get('/verification/request-object', async (req, res) => { this.presentationsReceivingService.getSignedRequestObject({req, res} )});
		app.get('/verification/definition', async (req, res) => { this.presentationsReceivingService.getPresentationDefinitionHandler({req, res}); });
		

		if (applicationMode == ApplicationModeType.ISSUER || applicationMode == ApplicationModeType.ISSUER_AND_VERIFIER) {
			app.get('/openid4vci/authorize', async (req, res) => {
				this.authorizationServerService.authorizationRequestHandler({req, res});
			});
			app.post('/openid4vci/token', async (req, res) => {
				this.authorizationServerService.tokenRequestHandler({req, res});
			});

			this.credentialIssuersService.exposeAllIssuers(app);
		}
	}

	private directPostEndpoint() {
		return async (req: any, res: any) => {
			try {
				await this.presentationsReceivingService.responseHandler({req, res});
				return;
			}
			catch(e) {
				console.error(e);
				return;
			}
		}
	}
}