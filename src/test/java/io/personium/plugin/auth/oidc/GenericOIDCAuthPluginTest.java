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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.auth.AuthenticatedIdentity;
import io.personium.test.categories.Unit;

/**
 * Unit test for OidcPluginExceptionTest.
 */
@Category({Unit.class})
public class GenericOIDCAuthPluginTest extends OIDCTestBase {

    /** Trusted client_id for testing. */
    static final List<String> TRUSTED_CLIENTID = Arrays.asList("dummy_client", "oidctestclient");

    /** Name of plugin for testing. */
    static final String PLUGIN_NAME = "Testing Plugin";

    /** Account type of plugin. */
    static final String ACCOUNT_TYPE = "oidc:testplugintype";

    /** Key for account name. */
    static final String ACCOUNT_NAME_KEY = "accountnamekey_test";

    /** GrantType of plugin. */
    static final String GRANT_TYPE = "urn:x-personium:oidc:plugintest";

    /**
     * Test that GenericOIDCAuthPlugin returns AuthenticatedIdentity specified in IdToken.
     */
    @Test
    public void GenericOIDCAuthPlugin_returns_AuthenticatedIdentity() {
        String testUserAccountName = "testuser";

        // configure
        try {
            GenericOIDCAuthPlugin plugin = new GenericOIDCAuthPlugin(CONFIGURATION_ENDPOINT_URL, TRUSTED_CLIENTID,
                    PLUGIN_NAME, ACCOUNT_TYPE, ACCOUNT_NAME_KEY, GRANT_TYPE);

            Map<String, List<String>> body = new HashMap<String, List<String>>();
            try {
                plugin.authenticate(body);
                fail("AuthPluginException is not called");
            } catch (Exception e) {
                assertEquals("Required parameter [id_token] missing.", e.getMessage());
            }

            // Generate id token
            Claims claims = Jwts.claims();
            claims.put(ACCOUNT_NAME_KEY, testUserAccountName);
            claims.setIssuer(ISSUER_STRING);
            claims.setAudience(TRUSTED_CLIENTID.get(0));
            String idToken = Jwts.builder().setHeaderParam(JwsHeader.KEY_ID, keyId).signWith(privateKey)
                    .setClaims(claims).compact();
            body.put("id_token", Arrays.asList(new String[] {idToken}));

            try {
                AuthenticatedIdentity ai = plugin.authenticate(body);
                assertEquals(testUserAccountName, ai.getAccountName());
                assertEquals(plugin.getAccountType(), ai.getAccountType());
            } catch (Exception e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        } catch (AuthPluginException e) {
            fail(e.getMessage());
        }

    }

    /**
     * Test that isProviderClientIdTrusted returns true if aud(client_id) in claims is trusted.
     */
    @Test
    public void isProviderClientIdTrusted_returns_true_if_aud_is_trusted() {

        Claims claims = Jwts.claims();
        claims.setAudience("dummy_client");

        Claims claimsMultipleAud = Jwts.claims();
        claimsMultipleAud.put("aud", new ArrayList<>(Arrays.asList("dummy_client", "dummy_client2")));

        Claims claimsNotTrusted = Jwts.claims();
        claimsNotTrusted.setAudience("dummy_client_not_trusted");

        try {
            GenericOIDCAuthPlugin plugin = new GenericOIDCAuthPlugin(CONFIGURATION_ENDPOINT_URL, TRUSTED_CLIENTID,
                    PLUGIN_NAME, ACCOUNT_TYPE, ACCOUNT_NAME_KEY, GRANT_TYPE);

            assertEquals(true, plugin.isProviderClientIdTrusted(claims));
            assertEquals(true, plugin.isProviderClientIdTrusted(claimsMultipleAud));
            assertEquals(false, plugin.isProviderClientIdTrusted(claimsNotTrusted));
        } catch (AuthPluginException e) {
            fail(e.getMessage());
        }
    }

    /**
     * Test that isProviderClientIdTrusted throws AuthPluginException if claims is expired.
     */
    @Test
    public void isProviderClientIdTrusted_throws_AuthPluginException_if_claims_is_expired() {

        Claims claims = Jwts.claims();
        Calendar cl = GregorianCalendar.getInstance();
        cl.set(1999, 11, 31);

        claims.setAudience("dummy_client").setExpiration(cl.getTime());

        String token = Jwts.builder().setHeaderParam(JwsHeader.KEY_ID, keyId).signWith(privateKey)
                .claim("exp", cl.getTimeInMillis() / 1000).compact();

        try {
            GenericOIDCAuthPlugin plugin = new GenericOIDCAuthPlugin(CONFIGURATION_ENDPOINT_URL, TRUSTED_CLIENTID,
                    PLUGIN_NAME, ACCOUNT_TYPE, ACCOUNT_NAME_KEY, GRANT_TYPE);

            Map<String, List<String>> body = new HashMap<String, List<String>>();
            body.put("id_token", Arrays.asList(token));
            plugin.authenticate(body);
            fail("No Exception is thrown");
            // assertEquals(true, plugin.isProviderClientIdTrusted(claims));
        } catch (AuthPluginException e) {
            assertTrue("Exception message is not matched.",
                    e.getMessage().startsWith("OpenID Connect ID Token Expired"));
        }
    }

}
