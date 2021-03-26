import type { JWE } from 'did-jwt'
import {
  HandlerMethods,
  RequestHandler,
  RPCConnection,
  RPCError,
  RPCRequest,
  RPCResponse,
  createHandler,
} from 'rpc-utils'
import { Ed25519Provider, encodeDID } from 'key-did-provder'
import { randomBytes } from '@stablelib/random'

const B64 = 'base64pad'

interface JWSSignature {
  protected: string
  signature: string
}

interface Context {
  did: string
  secretKey: Uint8Array
}

interface CreateJWSParams {
  payload: Record<string, any>
  protected?: Record<string, any>
  did: string
}

interface DecryptJWEParams {
  jwe: JWE
  did?: string
}

interface AuthParams {
  nonce: string
  aud: string
  paths: Array<string>
}

const ensureLink = async ({
  ceramic: CeramicApi,
  authProvider: AuthProvider,
  accountId: string,
  authedDid: string | null
}, did) => {
  if (authedDid !== did) {
    const proof = await authProvider.createLink(did)
    await doc.change({ content: proof })
  }
}

const didMethods: HandlerMethods<Context> = {
  did_authenticate: async (config: C10Config, params: AuthParams) => {
    // TODO - verify the caip10-link still points to our key did
    const response = await config.keyDid.send(params)
    return toGeneralJWS(response)
  },
  did_createJWS: async (config: C10Config, secretKey }, params: CreateJWSParams) => {
    // TODO - verify the caip10-link still points to our key did
    const requestDid = params.did.split('#')[0]
    // TODO - clean this up (proper did encoding)
    if (requestDid !== 'did:c10:' + config.accountId) throw new RPCError(4100, `Unknown DID: ${did}`)
    params.did = config.authedDid
    return config.keyDid.send(params)
  },
  did_decryptJWE: async (config: C10Config, params: DecryptJWEParams) => {
    return config.keyDid.send(params)
  },
}

interface C10Config {
  ceramic: CeramicApi
  authProvider: AuthProvider
  keyDid?: RPCConnection
  accountId?: AccountID
  linkDoc?: Doctype
  authedDid?: string | null
}

export class C10Provider implements RPCConnection {
  protected _handle: (msg: RPCRequest) => Promise<RPCResponse | null>

  constructor(config: C10Config) {
    if (!config.linkDoc || !config.accountId) {
      throw new Error('Please use the C10Provider.create function')
    }
    if (!config.keyDid) {
      config.keyDid = new Ed25519Provider(randomBytes(32))
    }
    const handler: RequestHandler = createHandler<Context>(didMethods)
    this._handle = (msg: RPCRequest) => {
      return handler(config, msg)
    }
  }

  static async create(config: C10Config) {
    config.accountId = AccountID.format(await config.authProvider.accountId())
    config.linkDoc = await config.ceramic.createDocument('caip10-link', {
      metadata: { controllers: [accountId] }
    }, { anchor: false })
    config.authedDid = doc?.content
    const { did } = await config.keyDid.send({})
    await ensureLink(config, did)
    config.authedDid = did
    return new C10Provider(config)
  }

  public get isDidProvider(): boolean {
    return true
  }

  public async send(msg: RPCRequest): Promise<RPCResponse | null> {
    return await this._handle(msg)
  }
}
