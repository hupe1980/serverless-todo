export interface Jwk {
    kty: string;
    use: string;
    kid: string;
    x5c: string;
    nbf?: string;
}
