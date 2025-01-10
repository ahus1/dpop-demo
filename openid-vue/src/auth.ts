import * as client from "openid-client";
import {
  Configuration,
  type DPoPOptions, type FetchBody,
  skipSubjectCheck,
  type TokenEndpointResponse,
  type TokenEndpointResponseHelpers
} from "openid-client";
import * as oauth from "oauth4webapi";

export async function init(server: URL, clientId: string, onSuccess: () => void) {
  let config = await client.discovery(server, clientId, undefined, undefined, {execute: [client.allowInsecureRequests],})

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

    let redirect_uri = window.location.href

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

    let tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers

    const DPoP = config.serverMetadata().dpop_signing_alg_values_supported ?
        client.getDPoPHandle(config, await client.randomDPoPKeyPair()) : undefined

    {

      let currentUrl: URL = new URL(window.location.href)
      tokens = await client.authorizationCodeGrant(config, currentUrl, {
        pkceCodeVerifier: code_verifier,
        expectedNonce: nonce,
        idTokenExpected: true,
      }, undefined, {DPoP})

      console.log('Token Endpoint Response', tokens)

    }

    initState(config, {DPoP}, tokens);

    onSuccess();

  }
}

let state: { config: Configuration; options: DPoPOptions, tokens: TokenEndpointResponse & TokenEndpointResponseHelpers}

export function initState(config: Configuration, options: DPoPOptions, tokens: TokenEndpointResponse & TokenEndpointResponseHelpers) {
  state = { config, options, tokens }
}

async function refreshOnDemand() {
  if (state.tokens.expiresIn() === 0) {
    await refresh();
  }
}

export async function refresh() {
  state.tokens = await client.refreshTokenGrant(state.config, state.tokens.refresh_token!, undefined, state.options);
}

export async function fetchUserInfo(): Promise<oauth.UserInfoResponse> {
  await refreshOnDemand();
  return client.fetchUserInfo(state.config, state.tokens.access_token, state.tokens.claims()!.sub, state.options);
}

export async function fetchProtectedResource(url: URL, method: string, body?: FetchBody, headers?: Headers): Promise<Response> {
  await refreshOnDemand();
  return client.fetchProtectedResource(state.config, state.tokens.access_token, url, method, body, headers, state.options);
}
