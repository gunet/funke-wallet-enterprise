import { CredentialView } from "../../authorization/types";
import { AuthorizationServerState } from "../../entities/AuthorizationServerState.entity";
import {  IssuanceFlow } from "../../openid4vci/Metadata";
import { VerifiableCredentialFormat, Display, CredentialSupported } from "../../types/oid4vci";
import { CredentialIssuer } from "./CredentialIssuer";


export interface SupportedCredentialProtocol {
	getCredentialIssuerConfig(): CredentialIssuer;
	getId(): string;
	getFormat(): VerifiableCredentialFormat;
	getTypes(): string[];
	getDisplay(): Display;

	getProfile(userSession: AuthorizationServerState): Promise<CredentialView | null>;
	generateCredentialResponse(userSession: AuthorizationServerState, holderDID: string): Promise<{ format?: VerifiableCredentialFormat, credential?: any, acceptance_token?: string }>;


	
	issuanceFlow(): IssuanceFlow;
	exportCredentialSupportedObject(): CredentialSupported;
}
