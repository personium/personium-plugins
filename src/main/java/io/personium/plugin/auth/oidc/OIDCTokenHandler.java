/**
 * Personium
 * Copyright 2014-2021 Personium Project Authors
 * - FUJITSU LIMITED
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.personium.plugin.auth.oidc;

import java.io.IOException;
import java.security.Key;

import org.apache.commons.lang.StringUtils;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.auth.AuthPluginUtils;
import io.personium.plugin.base.utils.PluginUtils;

/**
 * Class of handling IDToken of OIDC.
 */
public class OIDCTokenHandler {

    /** Issuer. */
    private String issuer = null;

    /** Jwks URI */
    private String jwksURI = null;

    /** Resolver of Jwk. */
    private JwkResolver jwkResolver = null;

    /** How many parts JWS contains. */
    private static final int PART_COUNT_JWS = 3;

    /** How many parts JWE contains. */
    private static final int PART_COUNT_JWE = 5;

    /**
     * Constructor of OIDCTokenHandler.
     * @param issuer issuer
     * @param jwks Jwks object
     */
    public OIDCTokenHandler(String issuer, String jwksURI) {
        if (StringUtils.isEmpty(jwksURI)) {
            throw new IllegalArgumentException("jwksUrl must not be empty");
        }
        this.issuer = issuer;
        this.jwksURI = jwksURI;
        this.jwkResolver = new JwkResolver(new JwkSet());
    }

    /**
     * Try parsing id token. jwtParser does not support encrypted IdToken(JWE).
     * @param idToken id token
     * @return claims
     */
    public Claims parseIdToken(String idToken) throws AuthPluginException {
        String[] parts = idToken.split("\\.");

        if (parts.length == PART_COUNT_JWS) {
            // check that key exists on Jwks.
            JSONObject header = null;
            try {
                header = (JSONObject) AuthPluginUtils.tokenToJSON(parts[0]);
            } catch (ParseException e) {
                throw new IllegalArgumentException("JWS Header is broken", e);
            }

            String kid = (String)header.get(JwsHeader.KEY_ID);
            String alg = (String)header.get(JwsHeader.ALGORITHM);
            Key key = this.jwkResolver.resolveSigningKey(kid, alg);
            if (key == null) {
                // refresh
                try {
                    JwkSet jwks = JwkSet.fetchJwks(jwksURI);
                    this.jwkResolver = new JwkResolver(jwks);
                } catch (IOException e) {
                    // cannot reach server
                    throw OidcPluginException.UNEXPECTED_RESPONSE.create(HttpGet.METHOD_NAME, jwksURI, "");
                } catch (ParseException e) {
                    // response is not JSON
                    throw OidcPluginException.UNEXPECTED_RESPONSE.create(jwksURI, "JSON");
                }
                key = this.jwkResolver.resolveSigningKey(kid, alg);
            }
            JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(key).build();
            Jws<Claims> jws = jwtParser.parseClaimsJws(idToken);
            Claims claims = jws.getBody();
            return claims;
        } else if (parts.length == PART_COUNT_JWE) {
            throw new IllegalArgumentException("JWE styled IdToken is not supported");
        } else {
            throw new IllegalArgumentException("Unknown IdToken");
        }
    }

    /**
     * Getter of issuer.
     * @return issuer
     */
    public String getIssuer() {
        return this.issuer;
    }


    /**
     * Create OIDCTokenHandle instance from configuration URL (For OpenID Connect Discovery 1.0).
     * @param configurationURL configuration URL.
     * @return OIDCTokenHandler
     * @throws AuthPluginException Exception thrown while initializing OIDCTokenHandler
     */
    public static OIDCTokenHandler createFromOIDCConfigurationURL(String configurationURL) throws AuthPluginException {
        try {
            JSONObject configurationJSON = PluginUtils.getHttpJSON(configurationURL);
            String jwksURI = (String) configurationJSON.get("jwks_uri");
            String issuer = (String) configurationJSON.get("issuer");
            if (jwksURI == null) {
                throw OidcPluginException.UNEXPECTED_RESPONSE.create(jwksURI, "non-null `jwks_uri`");
            }
            if (issuer == null) {
                throw OidcPluginException.UNEXPECTED_RESPONSE.create(issuer, "non-null `issuer`");
            }
            return new OIDCTokenHandler(issuer, jwksURI);
        } catch (ClientProtocolException e) {
            // exception with HTTP protocol
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(configurationURL, "proper HTTP response");
        } catch (IOException e) {
            // cannot reach server
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(HttpGet.METHOD_NAME, configurationURL, "");
        } catch (ParseException e) {
            // response is not JSON
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(configurationURL, "JSON");
        }
    }
}
