import {
  assertEquals,
  assertRejects,
} from "https://deno.land/std@0.185.0/testing/asserts.ts";
import * as src from "./main.ts";
import * as lib from "https://deno.land/x/jwe_cookie_map@v0.0.2/main.ts";
import { mergeHeaders } from "https://deno.land/std@0.185.0/http/cookie_map.ts";
import * as jose from "https://deno.land/x/jose@v4.14.4/util/errors.ts";

const sources = [src, lib];
const names = ["Local Source", "Latest Release"];
for (const index in sources) {
  const sourceCode = sources[index];
  const name = names[index];
  const JWECookieMap = sourceCode.JWECookieMap;
  const newCookieWithKeyPair = sourceCode.newCookieWithKeyPair;

  Deno.test(`${name} - Encrypted and decrypted payload shouls stay the same`, async () => {
    const headers = new Headers();
    const newCookies = new JWECookieMap(headers);
    const payload = { foo: "bar" };
    await newCookies.setEncrypted("key", payload);

    const cookie = mergeHeaders(newCookies).get("set-cookie");
    headers.set("Cookie", cookie!);
    const withCookies = new JWECookieMap(headers);
    await assertEquals(await withCookies.getDecrypted("key"), payload);
  });

  Deno.test(`${name} - Encryption should add configure claims`, async () => {
    const headers = new Headers();
    const newCookies = new JWECookieMap(headers);
    const now = new Date();
    newCookies.cookieConfiguration.encryptConfiguration = (jwt) =>
      jwt.setIssuedAt(now.getTime());
    const payload = { foo: "bar" };
    await newCookies.setEncrypted("key", payload);

    const cookie = mergeHeaders(newCookies).get("set-cookie");
    headers.set("Cookie", cookie!);
    const withCookies = new JWECookieMap(headers);
    await assertEquals(await withCookies.getDecrypted("key"), {
      ...payload,
      iat: now.getTime(),
    });
  });

  Deno.test(`${name} - Attempting to decrypt with a new keyPair should fail`, async () => {
    const headers = new Headers();
    const newCookies = new JWECookieMap(headers);
    const payload = { foo: "bar" };
    await newCookies.setEncrypted("key", payload);

    const cookie = mergeHeaders(newCookies).get("set-cookie");
    headers.set("Cookie", cookie!);
    const withCookies = await newCookieWithKeyPair(headers);
    await assertRejects(
      () => withCookies.getDecrypted("key"),
      jose.JWEDecryptionFailed,
    );
  });

  Deno.test(`${name} - Attempting to decrypt with a non encrypted value fail`, async () => {
    const headers = new Headers();
    const newCookies = new JWECookieMap(headers);
    const payload = { foo: "bar" };
    await newCookies.set("key", JSON.stringify(payload));

    const cookie = mergeHeaders(newCookies).get("set-cookie");
    headers.set("Cookie", cookie!);
    const withCookies = await newCookieWithKeyPair(headers);
    await assertRejects(() => withCookies.getDecrypted("key"), jose.JWEInvalid);
  });
}
