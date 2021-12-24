/**
 * Personium
 * Copyright 2021 Personium Project Authors
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

import java.util.Calendar;
import java.util.GregorianCalendar;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.test.categories.Unit;

/**
 * Unit test for OIDCTokenHandler.
 */
@Category({ Unit.class })
public class OIDCTokenHandlerTest extends OIDCTestBase {

    /**
     * Test that OIDCTokenHandler can handle correct token and parse claims from
     * jws.
     */
    @Test
    public void OIDCTokenHandler_can_handle_correct_token() {
        try {
            String claimKey = "key001";
            String claimValue = "val001";
            OIDCTokenHandler handler = OIDCTokenHandler
                    .createFromOIDCConfigurationURL(CONFIGURATION_ENDPOINT_URL);
            String token = Jwts.builder().setHeaderParam(JwsHeader.KEY_ID, keyId).signWith(privateKey)
                    .claim(claimKey, claimValue).compact();
            Claims claims = handler.parseIdToken(token);
            assertEquals(claimValue, claims.get(claimKey));
        } catch (AuthPluginException e) {
            fail(e.getMessage());
        }
    }

    /**
     * Test that OIDCTokenHandler throws when the token is expired.
     */
    @Test
    public void OIDCTokenHandler_can_throw_Exception_for_expired_token() {
        try {
            String claimKey = "key001";
            String claimValue = "val001";
            OIDCTokenHandler handler = OIDCTokenHandler
                    .createFromOIDCConfigurationURL(CONFIGURATION_ENDPOINT_URL);
            Calendar cl = GregorianCalendar.getInstance();
            cl.set(1999, 11, 31);
            String token = Jwts.builder().setHeaderParam(JwsHeader.KEY_ID, keyId).signWith(privateKey)
                    .claim(claimKey, claimValue).claim("exp", cl.getTimeInMillis() / 1000).compact();
            handler.parseIdToken(token);
            fail("Exception is not thrown");
        } catch (Exception e) {
            assertTrue("ExpiredJwtException is not thrown", e instanceof ExpiredJwtException);
        }
    }

    /**
     * Test that OIDCTokenHandler can reload JwkSet from IdP when IdP updates
     * JwkSet.
     * 
     * @throws Exception
     */
    @Test
    public void OIDCTokenHandler_can_reload_jwkset_if_updated() throws Exception {
        String claimKey = "key001";
        String claimValue = "val001";
        OIDCTokenHandler handler = OIDCTokenHandler.createFromOIDCConfigurationURL(CONFIGURATION_ENDPOINT_URL);
        String token = Jwts.builder().setHeaderParam(JwsHeader.KEY_ID, keyId).signWith(privateKey)
                .claim(claimKey, claimValue).compact();
        handler.parseIdToken(token);

        // update key pair
        this.prepareKeys();
        token = Jwts.builder().setHeaderParam(JwsHeader.KEY_ID, keyId).signWith(privateKey).claim(claimKey, claimValue)
                .compact();
        handler.parseIdToken(token);
    }
}
