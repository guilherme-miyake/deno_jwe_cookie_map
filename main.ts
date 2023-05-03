/**
Provides a iterable map interfaces for managing JWE cookies server side. Similar
to {@linkcode CookieMap}

By default the {@linkcode JWECookieMap} uses a automatically generated
"RSA-OAEP-256" key pair in the {@linkcode DEFAULT_CONFIG}, this value is not
persisted between executions.

{@linkcode newCookieWithKeyPair} is a helper functions to generate a
JWECookieMap with a new set of automatically generated key pair.

However the recommended use of this library, is loading your key pair and
creating a reusable instance of {@linkcode JWECookieConfiguration} with your
default cookie options.

@example
You can easily set encrypted cookies (JWEs) on your response and get
they decrypted payloads:

```ts
import { mergeHeaders } from "https://deno.land/std/http/cookie_map.ts";
import { JWECookieMap } from "https://deno.land/x/jwe_cookie_map/main.ts";

const initialRequestHeader = new Headers();
const response = new Response("hello", {
  headers: { "content-type": "text/plain" },
});
const initialCookies = new JWECookieMap(initialRequestHeader, { response });
const payload = { foo: "bar" };
await initialCookies.setEncrypted("key", payload);

// The cookie set on the first request will come on the next request from the client
const nextRequestHeaders = new Headers();
const cookie = mergeHeaders(initialCookies).get("set-cookie");
nextRequestHeaders.set("Cookie", cookie!);
const nextCookies = new JWECookieMap(nextRequestHeaders);
console.log(await nextCookies.getDecrypted("key")); // Expects to log { foo: "bar" }
```

@example
To access cookies not encrypted in a request and have any set keys
available for creating a response:

```ts
import { mergeHeaders } from "https://deno.land/std/http/cookie_map.ts";
import { JWECookieMap } from "https://deno.land/x/jwe_cookie_map/main.ts";

const request = new Request("https://localhost/", {
  headers: { "cookie": "foo=bar; bar=baz;" },
});

const cookies = new JWECookieMap(request, { secure: true });
console.log(cookies.get("foo")); // Expected to log "bar"
cookies.set("session", "1234567", { secure: true });
console.log(cookies.get("session")); // Expected to log undefined
const response = new Response("hello", {
  headers: mergeHeaders({
    "content-type": "text/plain",
  }, cookies),
});
```

@example
If you have a {@linkcode Response} or {@linkcode Headers} for a
response at construction of the cookies object, they can be passed and any set
cookies will be added directly to the response headers:

```ts
import { JWECookieMap } from "https://deno.land/x/jwe_cookie_map/main.ts";

const request = new Request("https://localhost/", {
  headers: { "cookie": "foo=bar; bar=baz;" },
});

const response = new Response("hello", {
  headers: { "content-type": "text/plain" },
});

const cookies = new JWECookieMap(request, { response });
console.log(cookies.get("foo")); // Expected to log "bar"
cookies.set("session", "1234567");
console.log(cookies.get("session")); // Expected to log undefined
```

@module
*/

import {
  CookieMap,
  CookieMapOptions,
  CookieMapSetDeleteOptions,
  Headered,
  jose,
} from "./deps.ts";

/**
 * Provides a way to configure the keys used for encryption, default options for cookies
 * and a way to add more jose.EncryptJWT configurations.
 */
export class JWECookieConfiguration {
  privateKey: jose.KeyLike | Uint8Array;
  publicKey: jose.KeyLike | Uint8Array;
  defaultOptions?: CookieMapOptions;
  encryptConfiguration: (jwt: jose.EncryptJWT) => jose.EncryptJWT;
  constructor(
    privateKey: jose.KeyLike | Uint8Array,
    publicKey: jose.KeyLike | Uint8Array,
    encryptConfiguration: (jwt: jose.EncryptJWT) => jose.EncryptJWT = (
      jwt: jose.EncryptJWT,
    ) => jwt,
  ) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.encryptConfiguration = encryptConfiguration;
  }
}

/**
 * Generates a new "RSA-OAEP-256" key pair and return a new
 * {@linkcode JWECookieConfiguration} instance with other default values
 */
export async function configWithNewKeyPair(): Promise<JWECookieConfiguration> {
  const keyPair = await jose.generateKeyPair("RSA-OAEP-256", {
    extractable: true,
  });
  return new JWECookieConfiguration(keyPair.privateKey, keyPair.publicKey);
}

/**
 * The default {@linkcode JWECookieConfiguration}} used by new {@linkcode JWECookieMap}
 * instance, comes with a automatically generated "RSA-OAEP-256" key pair that is not
 * persisted between executions.
 */
export const DEFAULT_CONFIG = await configWithNewKeyPair();

/**
 * Provides a way to manage encrypted cookies in a request and response on the server
 * as a single iterable collection. Extends {@linkcode CookieMap}.
 */
export class JWECookieMap extends CookieMap {
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

/**
 * Generates a new "RSA-OAEP-256" key pair and return a new
 * {@linkcode JWECookieMap} instance with other default values
 */
export async function newCookieWithKeyPair(
  request?: Headers | Headered,
  options?: CookieMapOptions,
) {
  return new JWECookieMap(
    request ?? new Headers(),
    options,
    await configWithNewKeyPair(),
  );
}
