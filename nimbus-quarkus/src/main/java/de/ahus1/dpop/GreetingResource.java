package de.ahus1.dpop;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.dpop.verifiers.AccessTokenValidationException;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DefaultDPoPSingleUseChecker;
import com.nimbusds.oauth2.sdk.dpop.verifiers.InvalidDPoPProofException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;
import com.nimbusds.openid.connect.sdk.Nonce;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.jboss.resteasy.reactive.RestHeader;
import org.jboss.resteasy.reactive.RestPath;

import java.io.IOException;
import java.net.ResponseCache;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Path("/hello")
public class GreetingResource {

    // The accepted DPoP proof JWS algorithms
    Set<JWSAlgorithm> acceptedAlgs = new HashSet<>(
            Arrays.asList(
                    JWSAlgorithm.RS256,
                    JWSAlgorithm.PS256,
                    JWSAlgorithm.ES256));

    // The max accepted age of the DPoP proof JWTs
    long proofMaxAgeSeconds = 60;

    long cachePurgeIntervalSeconds = 600;

    // DPoP single use checker, caches the DPoP proof JWT jti claims
    SingleUseChecker<Map.Entry<DPoPIssuer, JWTID>> singleUseChecker =
            new DefaultDPoPSingleUseChecker(
                    proofMaxAgeSeconds,
                    cachePurgeIntervalSeconds);

    // Create the DPoP proof and access token binding verifier,
    // the class is thread-safe
    DPoPProtectedResourceRequestVerifier verifier =
            new DPoPProtectedResourceRequestVerifier(
                    acceptedAlgs,
                    proofMaxAgeSeconds,
                    singleUseChecker);

    ClientID clientID = new ClientID("nimbus-quarkus");
    Secret clientSecret = new Secret("nimbus-quarkus-secret");
    ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

    @Context
    private UriInfo uriInfo;

    private volatile Nonce nonce = null;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response hello(
            @RestHeader("DPoP") String dpop,
            @RestPath String path,
            @RestHeader("Authorization") String authorization
    ) throws ParseException, GeneralException, URISyntaxException, IOException, InvalidDPoPProofException, AccessTokenValidationException, JOSEException {

        Issuer issuer = new Issuer("http://localhost:8080/realms/test");
        AuthorizationServerMetadata metadata = AuthorizationServerMetadata.resolve(issuer);

        // Verify some request

        // The HTTP request method and URL
        String httpMethod = "GET";
        URI httpURI = uriInfo.getRequestUri();

        if (dpop == null) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        // The DPoP proof, obtained from the HTTP DPoP header
        SignedJWT dPoPProof = SignedJWT.parse(dpop);

        // The DPoP access token, obtained from the HTTP Authorization header
        DPoPAccessToken inspectedToken = DPoPAccessToken.parse(authorization);

        // The introspection endpoint
        URI introspectionEndpoint = metadata.getIntrospectionEndpointURI();

        // Token to access the introspection endpoint, may need to be refreshed
        AccessToken accessToken = clientAccessToken(metadata);

        // Compose the introspection call
        HTTPRequest httpRequest = new TokenIntrospectionRequest(
                introspectionEndpoint,
                clientAuth,
                inspectedToken)
                .toHTTPRequest();

// Make the introspection call
        HTTPResponse httpResponse = httpRequest.send();

        TokenIntrospectionResponse tokenIntrospectionResponse = TokenIntrospectionResponse.parse(httpResponse);

        // The DPoP proof issuer, typically the client ID obtained from the
        // access token introspection
        DPoPIssuer dPoPIssuer = new DPoPIssuer(tokenIntrospectionResponse.toSuccessResponse().getClientID());

        // The JWK SHA-256 thumbprint confirmation, obtained from the
        // access token introspection
        JWKThumbprintConfirmation cnf = tokenIntrospectionResponse.toSuccessResponse().getJWKThumbprintConfirmation();

        if (nonce == null || !Objects.equals(dPoPProof.getJWTClaimsSet().getClaim("nonce"), nonce.getValue())) {
            nonce = new Nonce(UUID.randomUUID().toString());
            return Response
                    .status(401)
                    .type(MediaType.APPLICATION_JSON)
                    .header("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\",\n" +
                                                "   error_description=\"Resource server requires nonce in DPoP proof\"")
                    .header("DPoP-Nonce", nonce.getValue())
                    .build();
        }

        verifier.verify(httpMethod, httpURI, dPoPIssuer, dPoPProof,
                inspectedToken, cnf, nonce);

        nonce = null;

        return Response.ok("Hello from Quarkus REST\nToken introspection, DPoP and Nonce are good!").build();
    }

    private AccessToken clientAccessToken(AuthorizationServerMetadata metadata) throws URISyntaxException, IOException, com.nimbusds.oauth2.sdk.ParseException {
        // Construct the client credentials grant
        AuthorizationGrant clientGrant = new ClientCredentialsGrant();

        // The credentials to authenticate the client at the token endpoint


        // The request scope for the token (may be optional)
        Scope scope = new Scope();

        // The token endpoint
        URI tokenEndpoint = metadata.getTokenEndpointURI();

        // Make the token request
        TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, clientGrant, scope);

        TokenResponse response = TokenResponse.parse(request.toHTTPRequest().send());

        if (!response.indicatesSuccess()) {
            // We got an error response...
            TokenErrorResponse errorResponse = response.toErrorResponse();
            throw new RuntimeException(errorResponse.toErrorResponse().toString());
        }

        AccessTokenResponse successResponse = response.toSuccessResponse();

        // Get the access token
        AccessToken accessToken = successResponse.getTokens().getAccessToken();

        return accessToken;
    }
}
