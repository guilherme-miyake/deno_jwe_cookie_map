import {
  assertEquals,
  assertRejects,
} from "https://deno.land/std@0.185.0/testing/asserts.ts";
import JWECookieMap, { NewCookieWithKeyPair } from "./main.ts";
import { mergeHeaders } from "https://deno.land/std@0.185.0/http/cookie_map.ts";
import * as jose from "https://deno.land/x/jose@v4.14.4/util/errors.ts";

Deno.test("Encrypted and decrypted payload shouls stay the same", async () => {
  const headers = new Headers();
  const newCookies = new JWECookieMap(headers);
  const payload = { foo: "bar" };
  await newCookies.setEncrypted("key", payload);

  const cookie = mergeHeaders(newCookies).get("set-cookie");
  headers.set("Cookie", cookie!);
  const withCookies = new JWECookieMap(headers);
  await assertEquals(await withCookies.getDecrypted("key"), payload);
});

Deno.test("Encryption should add configure claims", async () => {
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

Deno.test("Attempting to decrypt with a new keyPair should fail", async () => {
  const headers = new Headers();
  const newCookies = new JWECookieMap(headers);
  const payload = { foo: "bar" };
  await newCookies.setEncrypted("key", payload);

  const cookie = mergeHeaders(newCookies).get("set-cookie");
  headers.set("Cookie", cookie!);
  const withCookies = await NewCookieWithKeyPair(headers);
  await assertRejects(
    () => withCookies.getDecrypted("key"),
    jose.JWEDecryptionFailed,
  );
});

Deno.test("Attempting to decrypt with a non encrypted value fail", async () => {
  const headers = new Headers();
  const newCookies = new JWECookieMap(headers);
  const payload = { foo: "bar" };
  await newCookies.set("key", JSON.stringify(payload));

  const cookie = mergeHeaders(newCookies).get("set-cookie");
  headers.set("Cookie", cookie!);
  const withCookies = await NewCookieWithKeyPair(headers);
  await assertRejects(() => withCookies.getDecrypted("key"), jose.JWEInvalid);
});
