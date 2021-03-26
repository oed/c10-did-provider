# c10 did provider
Extremely work in progress. A DID purely based on Ceramic caip10-links that generate ephemeral keys and links to them.

## Installation

TODO

## Usage

```js
import { C10Provider } from 'c10-did-provider'
import C10Resolver from 'c10-did-resolver'
import { DID } from 'dids'

const ceramic = // ...
const authProvider = // ... EthereumAuthProvider
const provider = await C10Resolver.create({ ceramic, authProvider })
const did = new DID({ provider, resolver: C10Resolver.getResolver() })
await did.authenticate()

// log the DID
console.log(did.id)

// create JWS
const { jws, linkedBlock } = await did.createDagJWS({ hello: 'world' })

// verify JWS
await did.verifyJWS(jws)

// create JWE
const jwe = await did.createDagJWE({ very: 'secret' }, [did.id])

// decrypt JWE
const decrypted = await did.decryptDagJWE(jwe)
```

## License

Apache-2.0 OR MIT
