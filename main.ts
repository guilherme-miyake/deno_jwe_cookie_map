import {
  CookieMap,
  CookieMapOptions,
  CookieMapSetDeleteOptions,
  Headered,
  jose,
} from "./deps.ts";

export class JWECookieConfiguration {
  privateKey: jose.KeyLike | Uint8Array;
  publicKey: jose.KeyLike | Uint8Array;
  defaultOptions?: CookieMapOptions;
  encryptConfiguration: (encryptChain: jose.EncryptJWT) => jose.EncryptJWT;
  constructor(
    privateKey: jose.KeyLike | Uint8Array,
    publicKey: jose.KeyLike | Uint8Array,
    encryptConfiguration: (encryptChain: jose.EncryptJWT) => jose.EncryptJWT = (
      jwt,
    ) => jwt,
  ) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.encryptConfiguration = encryptConfiguration;
  }
}

export const ConfigWithNewKeyPair = async () => {
  const keyPair = await jose.generateKeyPair("RSA-OAEP-256", {
    extractable: true,
  });
  return new JWECookieConfiguration(keyPair.privateKey, keyPair.publicKey);
};

export const DEFAULT_CONFIG = await ConfigWithNewKeyPair();

export default class JWECookieMap extends CookieMap {
  cookieConfiguration: JWECookieConfiguration;

  constructor(
    request: Headers | Headered,
    options?: CookieMapOptions,
    cookieConfiguration: JWECookieConfiguration = DEFAULT_CONFIG,
  ) {
    super(request, { ...cookieConfiguration, ...options });
    this.cookieConfiguration = cookieConfiguration;
    this.set = super.set;
    this.get = super.get;
    return this;
  }

  async setEncrypted(
    key: string,
    payload: jose.JWTPayload,
    options?: CookieMapSetDeleteOptions,
  ) {
    let jwt = new jose.EncryptJWT(payload)
      .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" });
    jwt = this.cookieConfiguration.encryptConfiguration(jwt);
    return this.set(
      key,
      await jwt.encrypt(this.cookieConfiguration.publicKey),
      options,
    );
  }

  async decryptedCookies() {
    const cookies: { [key: string]: jose.JWTPayload } = {};
    for (const [key, value] of this.entries()) {
      const jwt = await jose.jwtDecrypt(
        value,
        this.cookieConfiguration.privateKey,
      );
      cookies[key] = jwt.payload;
    }
    return cookies;
  }

  async setMultipleEncryptedPayloas(
    payloads: { [key: string]: jose.JWTPayload },
    options?: CookieMapSetDeleteOptions,
  ) {
    await Promise.all(
      Object.entries(payloads).map(([key, value]) => {
        return this.setEncrypted(key, value, options);
      }),
    );
  }

  async getDecrypted(key: string) {
    if (this.get(key) == undefined) return undefined;
    const jwt = await jose.jwtDecrypt(
      this.get(key)!,
      this.cookieConfiguration.privateKey,
    );
    return jwt.payload;
  }
}

export const NewCookieWithKeyPair = async (
  request?: Headers | Headered,
  options?: CookieMapOptions,
) => {
  return new JWECookieMap(
    request ?? new Headers(),
    options,
    await ConfigWithNewKeyPair(),
  );
};
