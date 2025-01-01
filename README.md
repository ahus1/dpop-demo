# Steps

* Run Keycloak with feature dpop enabled
* Create client with URLs http://localhost:5173/ and http://localhost:4173/
* Activate DPoP for the client to enforce it - otherwise the client can choose to use DPoP when creating the tokens via the code-to-token or the refresh token reques

* https://danielfett.de/2020/05/04/dpop-attacker-model/

* Attacks mitigated -> Access token stolen or pre-computed at client, replay attacks, exchange token with different URL
* Not mitigated -> XSS to the client (even if key is safe, the attacker can create arbitrary access tokens)

# dpop

This template should help get you started developing with Vue 3 in Vite.

## Recommended IDE Setup

[VSCode](https://code.visualstudio.com/) + [Volar](https://marketplace.visualstudio.com/items?itemName=Vue.volar) (and disable Vetur).

## Type Support for `.vue` Imports in TS

TypeScript cannot handle type information for `.vue` imports by default, so we replace the `tsc` CLI with `vue-tsc` for type checking. In editors, we need [Volar](https://marketplace.visualstudio.com/items?itemName=Vue.volar) to make the TypeScript language service aware of `.vue` types.

## Customize configuration

See [Vite Configuration Reference](https://vite.dev/config/).

## Project Setup

```sh
npm install
```

### Compile and Hot-Reload for Development

```sh
npm run dev
```

### Type-Check, Compile and Minify for Production

```sh
npm run build
```
