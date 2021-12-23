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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.RSAPublicKeySpec;

import org.apache.commons.lang.RandomStringUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.junit.After;
import org.junit.Before;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import io.jsonwebtoken.SignatureAlgorithm;
import io.personium.plugin.base.utils.PluginUtils;

/**
 * Base class of OIDCTestBase. This test class prepares dummy KeyPair and dummy OIDC Configuration Endpoint.
 */
public abstract class OIDCTestBase {

    /** Mock for static PluginUtils class. */
    MockedStatic<PluginUtils> mockedPluginUtils;

    /** Key size of key generated. */
    static final int KEY_SIZE = 2048;

    /** OpenID discovery configuration url (mocked). */
    static final String CONFIGURATION_ENDPOINT_URL = "https://localhost/.well-known/openid-configuration";

    /** Issuer (mocked). */
    static final String ISSUER_STRING = "https://localhost/";

    /** Key type of key generated. */
    String keyType = "RSA";

    /** Key id specified in jwks. */
    String keyId = "";

    /** Key alg specified in jwks (After being generated). */
    String keyAlg = "";

    /** Private Key to sign */
    PrivateKey privateKey = null;

    /** JwkSet response */
    private JSONObject jsonJwks = null;

    /**
     * Setter of JwkSet
     * @param keys JSONArray of keys
     */
    @SuppressWarnings("unchecked")
    protected void setJwkSet(JSONArray keys) {
        jsonJwks = new JSONObject();
        jsonJwks.put("keys", keys);
    }

    /**
     * Getter of JwkSet
     */
    protected JSONObject getJwkSet() {
        return this.jsonJwks;
    }

    /**
     * This function prepares new KeyPair.
     */
    @SuppressWarnings("unchecked")
    protected void prepareKeys() throws Exception {
        this.keyType = "RSA";
        KeyPairGenerator kg = KeyPairGenerator.getInstance(keyType);
        kg.initialize(KEY_SIZE);
        KeyPair keyPair = kg.generateKeyPair();
        KeyFactory factory = KeyFactory.getInstance(keyType);
        this.privateKey = keyPair.getPrivate();
        
        this.keyId = RandomStringUtils.randomAlphanumeric(32).toUpperCase();
        this.keyAlg = SignatureAlgorithm.forSigningKey(privateKey).getValue();

        RSAPublicKeySpec publicKeySpec = factory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
        BigInteger n = publicKeySpec.getModulus();
        BigInteger e = publicKeySpec.getPublicExponent();

        JSONArray arrJwk = new JSONArray();
        JSONObject testJwk = new JSONObject();
        testJwk.put(Jwk.KEY_TYPE, keyType);
        testJwk.put("n", PluginUtils.encodeBase64Url(n.toByteArray()));
        testJwk.put("e", PluginUtils.encodeBase64Url(e.toByteArray()));
        testJwk.put(Jwk.KEY_ID, keyId);
        testJwk.put(Jwk.ALGORITHM, keyAlg);
        arrJwk.add(testJwk);
        this.setJwkSet(arrJwk);
    }

    /**
     * Prepare dummy KeyPair and setup mock of PluginUtils.
     * @throws Exception Exception thrown while initializing.
     */
    @Before
    @SuppressWarnings("unchecked")
    public void prepare() throws Exception {

        /** Preparing dummy KeyPair */
        prepareKeys();

        /** Setup mock */
        mockedPluginUtils = Mockito.mockStatic(PluginUtils.class);

        JSONObject dummyConfig = new JSONObject();
        dummyConfig.put("jwks_uri", "https://localhost/jwks");
        dummyConfig.put("issuer", ISSUER_STRING);

        mockedPluginUtils.when(() -> {
            PluginUtils.getHttpJSON(CONFIGURATION_ENDPOINT_URL);
        }).thenReturn(dummyConfig);

        mockedPluginUtils.when(() -> {
            PluginUtils.getHttpJSON("https://localhost/jwks");
        }).then(new Answer<JSONObject>() {
            @Override
            public JSONObject answer(InvocationOnMock invocation) throws Throwable {
                return getJwkSet();
            }
        });

        mockedPluginUtils.when(() -> {
            PluginUtils.decodeBase64Url(Mockito.anyString());
        }).thenCallRealMethod();

        mockedPluginUtils.when(() -> {
            PluginUtils.encodeBase64Url((byte[]) Mockito.any());
        }).thenCallRealMethod();
    }

    /**
     * Close mock of PluginUtils.
     */
    @After
    public void cleanup() {
        mockedPluginUtils.close();
    }
}
