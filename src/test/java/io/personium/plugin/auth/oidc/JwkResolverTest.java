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
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultJwsHeader;
import io.personium.plugin.base.utils.PluginUtils;
import io.personium.test.categories.Unit;

/**
 * Test of JwkResovler.
 */
@Category({Unit.class})
public class JwkResolverTest {

    /**
     * Test that JwkResolver can resolve key from Json Web Key Set.
     */
    @Test
    @SuppressWarnings("unchecked")
    public void JwkResolver_can_resolve_key() {
        try {
            String keyType = "RSA";
            KeyPairGenerator kg = KeyPairGenerator.getInstance(keyType);
            kg.initialize(1024);
            KeyPair keyPair = kg.generateKeyPair();
            KeyFactory factory = KeyFactory.getInstance(keyType);
            RSAPublicKeySpec publicKeySpec = factory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
            PublicKey publicKey = factory.generatePublic(publicKeySpec);
            BigInteger n = publicKeySpec.getModulus();
            BigInteger e = publicKeySpec.getPublicExponent();

            JSONObject jsonJwks = new JSONObject();
            JSONArray arrJwk = new JSONArray();
            JSONObject testJwk = new JSONObject();
            testJwk.put(Jwk.KEY_TYPE, keyType);
            testJwk.put("n", PluginUtils.encodeBase64Url(n.toByteArray()));
            testJwk.put("e", PluginUtils.encodeBase64Url(e.toByteArray()));
            testJwk.put(Jwk.KEY_ID, "test_kid");
            testJwk.put(Jwk.ALGORITHM, "test_alg");
            arrJwk.add(testJwk);
            jsonJwks.put("keys", arrJwk);

            DefaultJwsHeader header = new DefaultJwsHeader();
            header.setAlgorithm("test_alg");
            header.setKeyId("test_kid");
            JwkResolver resolver = new JwkResolver(JwkSet.parseJSON(jsonJwks));
            Key resultKey = resolver.resolveSigningKey(header, (Claims) null);
            assertEquals(publicKey, resultKey);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

}
