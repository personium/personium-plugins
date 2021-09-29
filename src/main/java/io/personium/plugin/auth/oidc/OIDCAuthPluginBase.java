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

import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import io.personium.plugin.base.PluginLog;
import io.personium.plugin.base.auth.AuthConst;
import io.personium.plugin.base.auth.AuthPlugin;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.auth.AuthenticatedIdentity;

/**
 * Base of OIDCAuthPlugin.
 */
public abstract class OIDCAuthPluginBase implements AuthPlugin {

    /** String for toString method. */
    public static final String PLUGIN_TOSTRING = "Generic OpenID Connect Authentication";

    /** Key for id token. */
    public static final String KEY_TOKEN = "id_token";

    /** OIDC token handler. */
    private OIDCTokenHandler tokenHandler = null;

    /**
     * Constructor of OIDCAuthPlugin.
     * @param configURL URL of well-known openid-configuration for IdP
     * @throws AuthPluginException Exception thrown while initializing
     */
    protected OIDCAuthPluginBase(String configURL) throws AuthPluginException {
        tokenHandler = OIDCTokenHandler.createFromOIDCConfigurationURL(configURL);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return PLUGIN_TOSTRING;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getType() {
        return AuthConst.PLUGIN_TYPE;
    }

    /**
     * Define method for generating AuthenticatedIdentity from claims.
     * @param claims claims contained in id token
     * @return AuthenticatedIdentity
     */
    protected abstract AuthenticatedIdentity parseClaimsToAuthenticatedIdentity(Claims claims);

    /**
     * Abstract method for determining the provided audience is trusted.
     * @param claims claims containerd in id token
     * @return true if client_id is trusted
     */
    protected abstract boolean isProviderClientIdTrusted(Claims claims);

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthenticatedIdentity authenticate(Map<String, List<String>> body) throws AuthPluginException {
        if (body == null) {
            OidcPluginException.REQUIRED_PARAM_MISSING.create("Body");
        }

        String idToken = null;

        // get idToken from body
        List<String> idTokenList = body.get(KEY_TOKEN);
        if (idTokenList == null) {
            throw OidcPluginException.REQUIRED_PARAM_MISSING.create(KEY_TOKEN);
        }
        idToken = idTokenList.get(0);
        if (StringUtils.isEmpty(idToken)) {
            throw OidcPluginException.REQUIRED_PARAM_MISSING.create(KEY_TOKEN);
        }

        Claims claims = null;

        try {
            claims = tokenHandler.parseIdToken(idToken);
        } catch (ExpiredJwtException e) {
            // Is not the token expired
            Date expiration = e.getClaims().getExpiration();
            throw OidcPluginException.EXPIRED_ID_TOKEN.create(expiration.getTime());
        } catch (MalformedJwtException | IllegalArgumentException e) {
            throw OidcPluginException.INVALID_ID_TOKEN.create("malformed jwt token is passed");
        } catch (SignatureException e) {
            // IdToken contains wrong signature
            throw OidcPluginException.INVALID_ID_TOKEN.create("ID Token sig value is invalid");
        } catch (Exception e) {
            throw OidcPluginException.INVALID_ID_TOKEN.create(e.getMessage());
        }

        String issuer = claims.getIssuer();

        // check that issuer is specified
        if (issuer == null || !issuer.equals(tokenHandler.getIssuer())) {
            PluginLog.OIDC.INVALID_ISSUER.params(issuer).writeLog();
            throw OidcPluginException.AUTHN_FAILED.create();
        }

        // check that client_id is trusted
        if (!this.isProviderClientIdTrusted(claims)) {
            throw OidcPluginException.WRONG_AUDIENCE.create(claims.getAudience());
        }

        return this.parseClaimsToAuthenticatedIdentity(claims);
    }
}
