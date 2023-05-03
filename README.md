# Deno - JWE Cookie Module

Provides a iterable map interfaces for managing JWE cookies server side. Similar
to [CookieMap](https://deno.land/std/http/cookie_map.ts).

By default the
[JWECookieMap](https://deno.land/x/jwe_cookie_map/main.ts?s=JWECookieMap) uses a
automatically generated "RSA-OAEP-256" key pair in the
[DEFAULT_CONFIG](https://deno.land/x/jwe_cookie_map/main.ts?s=DEFAULT_CONFIG) ,
this value is not persisted between executions.

[newCookieWithKeyPair](https://deno.land/x/jwe_cookie_map/main.ts?s=newCookieWithKeyPair)
is a helper functions to generate a
[JWECookieMap](https://deno.land/x/jwe_cookie_map/main.ts?s=JWECookieMap) with a
new set of automatically generated key pair.

However the recommended use of this library, is loading your key pair and
creating a reusable instance of
[JWECookieConfiguration](https://deno.land/x/jwe_cookie_map/main.ts?s=JWECookieConfiguration)
with your default cookie options.

## Documentation

Browse the [Full Documentation](https://deno.land/x/jwe_cookie_map/main.ts) with examples on Deno Land.
