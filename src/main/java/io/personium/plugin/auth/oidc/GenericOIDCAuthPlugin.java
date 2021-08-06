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

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.RequiredTypeException;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.auth.AuthenticatedIdentity;

/**
 * Implementation of GenericOIDCAuthPlugin
 */
public class GenericOIDCAuthPlugin extends OIDCAuthPluginBase {

    /** Logger */
    static Logger log = LoggerFactory.getLogger(GenericOIDCAuthPlugin.class);

    /** OpenID Connect Configuration Endpoint URL */
    final String configurationEndpointURL;

    /** Trusted Client Ids */
    final List<String> trustedClientIds;

    /** Customized plugin name */
    final String pluginName;

    /** Customized account type */
    final String accountType;

    /** Customized account name key in claims */
    final String accountNameKey;

    /** Customized grant type */
    final String grantType;

    /**
     * Constructor of OIDCAuthPlugin
     * @param configurationEndpointURL
     * @param trustedCliendIds
     * @param pluginName
     * @param accountType
     * @param accountNameKey
     * @param grantType
     */
    public GenericOIDCAuthPlugin(String configurationEndpointURL,
        List<String> trustedCliendIds,
        String pluginName,
        String accountType,
        String accountNameKey,
        String grantType ) throws AuthPluginException {
            super(configurationEndpointURL);
            this.configurationEndpointURL = configurationEndpointURL;
            this.trustedClientIds = trustedCliendIds;
            this.pluginName = pluginName;
            this.accountType = accountType;
            this.accountNameKey = accountNameKey;
            this.grantType = grantType;
        }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return pluginName;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getAccountType() {
        return accountType;
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public String getGrantType() {
        return grantType;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected AuthenticatedIdentity parseClaimsToAuthenticatedIdentity(Claims claims) {
        AuthenticatedIdentity ai = new AuthenticatedIdentity();
        ai.setAccountName((String)claims.get(accountNameKey));
        ai.setAccountType(accountType);
        return ai;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @SuppressWarnings("unchecked")
    boolean isProviderClientIdTrusted(Claims claims) {
        if (trustedClientIds.contains("*")) return true;

        // Try to parse audience as ArrayList
        List<String> audiencesList = new ArrayList<String>();
        try {
            ArrayList<String> auds = claims.get("aud", ArrayList.class);
            audiencesList.addAll(auds);
        } catch (RequiredTypeException e ) {
            // get audience as String
            String audience = claims.getAudience();
            audiencesList.add(audience);
        }

        for (String client_id : trustedClientIds) {
            if (audiencesList.contains(client_id)) return true;
        }

        return false;
    }

}
