/**
 * Personium
 * Copyright 2021 Personium Project Authors
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

import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.utils.PluginUtils;

/**
 * Class of handling IDToken of OIDC
 */
public class OIDCTokenHandler {

    /** Issuer */
    private String issuer = null;

    /** Resolver of Jwk */
    private JwksResolver jwksResolver = null;

    /** Jwt Parser */
    private JwtParser jwtParser = null;
    
    /**
     * Constructor of OIDCTokenHandler
     * @param issuer issuer
     * @param jwks Jwks object
     */
    public OIDCTokenHandler(String issuer, Jwks jwks) {
        if (jwks == null) throw new IllegalArgumentException("jwks must not be null");
        this.issuer = issuer;
        this.jwksResolver = new JwksResolver(jwks);
        this.jwtParser = Jwts.parserBuilder().setSigningKeyResolver(this.jwksResolver).build();
    }

    /**
     * Try parsing id token
     * @param idToken id token
     * @return claims
     */
    public Claims parseIdToken(String idToken) {
        Jws<Claims> jws = this.jwtParser.parseClaimsJws(idToken);
        Claims claims = jws.getBody();
        return claims;
    }

    /**
     * Getter of issuer
     * @return issuer
     */
    public String getIssuer() {
        return this.issuer;
    }

    /**
     * Create OIDCTokenHandle instance with specified issuer and jwksURI.
     * @param issuer Identifier of issuer
     * @param jwksURI URL for retrieving json web keys
     * @return OIDCTokenHandler
     * @throws AuthPluginException Exception thrown while initializing OIDCTokenHandler
     */
    public static OIDCTokenHandler create(String issuer, String jwksURI) throws AuthPluginException {
        try {
            JSONArray jsonJwks = (JSONArray)PluginUtils.getHttpJSON(jwksURI).get("keys");
            Jwks jwks = new Jwks(jsonJwks);
            return new OIDCTokenHandler(issuer, jwks);
        } catch (ClientProtocolException e) {
            // exception with HTTP procotol
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(jwksURI, "proper HTTP response");
        } catch (IOException e) {
            // cannot reach server
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(HttpGet.METHOD_NAME, jwksURI, "");
        } catch (ParseException e) {
            // response is not JSON
            throw OidcPluginException.UNEXPECTED_RESPONSE.create(jwksURI, "JSON");
        }
    }

    /**
     * Create OIDCTokenHandle instance from configuration URL (For OpenID Connect Discovery 1.0)
     * @param configurationURL configuration URL.
     * @return OIDCTokenHandler
     * @throws AuthPluginException Exception thrown while initializing OIDCTokenHandler
     */
    public static OIDCTokenHandler createFromOIDCConfigurationURL(String configurationURL) throws AuthPluginException {
        try {
            JSONObject configurationJSON = PluginUtils.getHttpJSON(configurationURL);
            String jwksURI = (String) configurationJSON.get("jwks_uri");
            String issuer = (String) configurationJSON.get("issuer");
            return create(issuer, jwksURI);
        } catch (ClientProtocolException e) {
            // exception with HTTP procotol
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