import './assets/main.css'

import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import * as client from 'openid-client'

// Prerequisites

let getCurrentUrl!: (...args: any) => URL
let server!: URL // Authorization server's Issuer Identifier URL
let clientId!: string
let clientSecret!: string
/**
 * Value used in the authorization request as redirect_uri pre-registered at the
 * Authorization Server.
 */
let redirect_uri!: string

// End of prerequisites

server = new URL('http://localhost:8080/realms/master')
clientId = 'test'

let config = await client.discovery(server, clientId, undefined, undefined, {     execute: [client.allowInsecureRequests],   } )

let code_challenge_method = 'S256'
/**
 * The following (code_verifier and potentially nonce) MUST be generated for
 * every redirect to the authorization_endpoint. You must store the
 * code_verifier and nonce in the end-user session such that it can be recovered
 * as the user gets redirected from the authorization server back to your
 * application.
 */
let nonce!: string | undefined

let code_verifier!: string | undefined

// Further parsing:
const params = new URLSearchParams(window.location.search);

if (!params.has('code')) {
    code_verifier = client.randomPKCECodeVerifier()
    sessionStorage.setItem("codeVerifier", code_verifier);
    let code_challenge = await client.calculatePKCECodeChallenge(code_verifier)

    redirect_uri = window.location.href

    // redirect user to as.authorization_endpoint
    let parameters: Record<string, string> = {
        redirect_uri,
        scope: 'openid email',
        code_challenge,
        code_challenge_method,
    }

    /**
     * We cannot be sure the AS supports PKCE so we're going to use nonce too. Use
     * of PKCE is backwards compatible even if the AS doesn't support it which is
     * why we're using it regardless.
     */
    if (!config.serverMetadata().supportsPKCE()) {
        nonce = client.randomNonce()
        sessionStorage.setItem("nonce", nonce);
        parameters.nonce = nonce
    } else {
        sessionStorage.removeItem("nonce");
    }

    let redirectTo = client.buildAuthorizationUrl(config, parameters)

    console.log('redirecting to', redirectTo.href)
    window.location.href = redirectTo.href
} else {
// one eternity later, the user lands back on the redirect_uri
// Authorization Code Grant

    code_verifier = sessionStorage.getItem("codeVerifier") || undefined;
    if (code_verifier) {
        sessionStorage.removeItem("codeVerifier")
    }
    nonce = sessionStorage.getItem("nonce") || undefined;
    if (nonce) {
        sessionStorage.removeItem("nonce")
    }

    let sub: string
    let access_token: string
    let refresh_token: string | undefined
    const DPoP = config.serverMetadata().dpop_signing_alg_values_supported ?
        client.getDPoPHandle(config, await client.randomDPoPKeyPair()) : undefined

    {

        let currentUrl: URL = new URL(window.location.href)
        let tokens = await client.authorizationCodeGrant(config, currentUrl, {
            pkceCodeVerifier: code_verifier,
            expectedNonce: nonce,
            idTokenExpected: true,
        }, undefined, { DPoP })

        console.log('Token Endpoint Response', tokens)
        ;({access_token, refresh_token} = tokens)
        let claims = tokens.claims()!
        console.log('ID Token Claims', claims)
        ;({sub} = claims)

        console.log("search: " + window.location.search)
        window.history.replaceState({}, document.title, window.location.pathname);
        console.log("search: " + window.location.search)

    }


// UserInfo Request
    {
        let userInfo = await client.fetchUserInfo(config, access_token, sub, { DPoP })

        console.log('UserInfo Response', userInfo)
    }

    {
        let headers = new Headers()
        headers.set('accept', 'application/json')
        headers.append('accept', 'application/jwt')
        let anyProtected = await client.fetchProtectedResource(config, access_token, new URL('http://localhost:8080/realms/master/protocol/openid-connect/userinfo')
        , 'GET', undefined, headers, { DPoP } );
        console.log('Any Protected Response', anyProtected)
    }

    {
        if (refresh_token) {
            // get tokens without DPoP -> if enabled for a client, this is enforced
            let tokens = await client.refreshTokenGrant(config, refresh_token, undefined, { DPoP });
            ;({access_token, refresh_token} = tokens)
            console.log('Refresh Token', tokens)
        }
    }


    const app = createApp(App)

    app.use(router)

    app.mount('#app')

    console.log("search: " + window.location.search)

    router.replace({ path: window.location.pathname })

    console.log("search: " + window.location.search)

}
