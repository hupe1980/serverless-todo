import axios from 'axios';

import { certToPEM } from './utils';

let jwksCache = [];

export class JwksClient {
  constructor(private readonly jwksUrl: string) {}

  private async getJwks() {
    if (jwksCache.length) return jwksCache;

    const res = await axios.get(this.jwksUrl);
    const jwks = res.data.keys;

    jwksCache = jwks;

    return jwks;
  }

  private async getSigningKeys() {
    const jwks = await this.getJwks();

    console.log('JWKS', jwks)

    if (!jwks || !jwks.length) {
      throw new Error('The JWKS endpoint did not contain any keys');
    }

    const signingKeys = jwks
      .filter(
        key =>
          key.use === 'sig' && // JWK property `use` determines the JWK is for signing
          key.kty === 'RSA' && // We are only supporting RSA
          key.kid && // The `kid` must be present to be useful for later
          key.x5c &&
          key.x5c.length // Has useful public keys (we aren't using n or e)
      )
      .map(key => ({
        kid: key.kid,
        nbf: key.nbf,
        publicKey: certToPEM(key.x5c[0])
      }));

    if (!signingKeys.length) {
      throw new Error('The JWKS endpoint did not contain any signing keys');
    }

    return signingKeys;
  }

  public async getSigningKey(kid: string) {
    const keys = await this.getSigningKeys();

    const signingKey = keys.find(key => key.kid === kid);

    if (!signingKey) {
      throw new Error(`Unable to find a signing key that matches '${kid}'`);
    }

    return signingKey;
  }
}
