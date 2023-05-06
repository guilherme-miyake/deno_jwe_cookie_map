import { JWECookieMap, newCookieWithKeyPair } from "./mod.ts";
import { CookieMap } from "./deps.ts";
import { mergeHeaders } from "./deps.ts";

const headers = new Headers();
Deno.bench(function createDefault() {
  new CookieMap(headers);
});

Deno.bench(function createDefaultJWE() {
  new JWECookieMap(headers);
});

Deno.bench(async function createNewJWE() {
  await newCookieWithKeyPair();
});

Deno.bench(function setDefault() {
  const newCookie = new JWECookieMap(headers);
  newCookie.set("cookiekey", JSON.stringify({ foo: "bar" }));
});

Deno.bench(async function setEncrypted() {
  const newCookie = new JWECookieMap(headers);
  await newCookie.setEncrypted("key", { foo: "bar" });
});

let emptyCookie = new JWECookieMap(headers);
emptyCookie.set("default", JSON.stringify({ foo: "bar" }));
let cookie = mergeHeaders(emptyCookie).get("set-cookie");
headers.set("Cookie", cookie!);
let withCookies = new JWECookieMap(headers);

Deno.bench(function getDefault() {
  withCookies.get("default");
});

emptyCookie = new JWECookieMap(headers);
await emptyCookie.setEncrypted("encrypted", { foo: "bar" });
cookie = mergeHeaders(emptyCookie).get("set-cookie");
headers.set("Cookie", cookie!);
withCookies = new JWECookieMap(headers);

Deno.bench(async function getEncrypted() {
  await withCookies.getDecrypted("encrypted");
});
