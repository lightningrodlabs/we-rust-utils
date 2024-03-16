/* tslint:disable */
/* eslint-disable */

/* auto-generated by NAPI-RS */

export function defaultConductorConfig(adminPort: number, conductorEnvironmentPath: string, keystoreConnectionUrl: string, bootstrapServerUrl: string, signalingServerUrl: string): string
export function saveHappOrWebhapp(happOrWebHappPath: string, uisDir: string, happsDir: string): Promise<string>
/** Checks that the happ or webhapp is of the correct format */
export function validateHappOrWebhapp(happOrWebhappBytes: Array<number>): Promise<string>
export interface ZomeCallUnsignedNapi {
  cellId: Array<Array<number>>
  zomeName: string
  fnName: string
  payload: Array<number>
  capSecret?: Array<number>
  provenance: Array<number>
  nonce: Array<number>
  expiresAt: number
}
export interface ZomeCallNapi {
  cellId: Array<Array<number>>
  zomeName: string
  fnName: string
  payload: Array<number>
  capSecret?: Array<number>
  provenance: Array<number>
  nonce: Array<number>
  expiresAt: number
  signature: Array<number>
}
export type JsWeRustHandler = WeRustHandler
export class WeRustHandler {
  constructor()
  static connect(keystoreUrl: string, passphrase: string): Promise<WeRustHandler>
  signZomeCall(zomeCallUnsignedJs: ZomeCallUnsignedNapi): Promise<ZomeCallNapi>
}
export type JsZomeCallSigner = ZomeCallSigner
export class ZomeCallSigner {
  constructor()
  static connect(connectionUrl: string, passphrase: string): Promise<ZomeCallSigner>
  signZomeCall(zomeCallUnsignedJs: ZomeCallUnsignedNapi): Promise<ZomeCallNapi>
}
