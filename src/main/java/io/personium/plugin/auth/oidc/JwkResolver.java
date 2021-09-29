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

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

import org.json.simple.JSONObject;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.UnsupportedJwtException;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.utils.PluginUtils;

/**
 * Resolver of json web key for io.jsonwebtoken.JwtParser.
 */
public class JwkResolver extends SigningKeyResolverAdapter {

    /** json web key set. */
    private JwkSet jwkSet;

    /**
     * Constructor of JwksResolver.
     * @param jwkSet Jwks object containing json web key.
     */
    public JwkResolver(JwkSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @SuppressWarnings("rawtypes")
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        /**
         * Resolve Signing key specified in JwsHeader. It must be considered that `jku` and `jws` parameter, but this
         * class does not support yet.
         */
        String kid = header.getKeyId();
        String alg = header.getAlgorithm();

        List<JSONObject> listJwk = jwkSet.getKeys();
        for (JSONObject jsonJwk : listJwk) {
            if (kid == null || !kid.equals(jsonJwk.get(Jwk.KEY_ID))) {
                continue;
            }
            if (alg == null || !alg.equals(jsonJwk.get(Jwk.ALGORITHM))) {
                continue;
            }
            // matched
            try {
                return generateKeyFromJwk(jsonJwk);
            } catch (IllegalArgumentException | NoSuchAlgorithmException e) {
                throw new UnsupportedJwtException("Failed to resolve a signing key.", e);
            }
        }
        // not found
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @SuppressWarnings("rawtypes")
    public Key resolveSigningKey(JwsHeader header, String payload) {
        /** `payload` is not needed while resolving signing key. */
        return resolveSigningKey(header, (Claims) null);
    }

    /**
     * Generate public key from JSON Web Key document.
     * @param jsonJwk JSON of JSON Web Key.
     * @return public key
     * @throws AuthPluginException Exception thrown during generating key.
     */
    private Key generateKeyFromJwk(JSONObject jsonJwk) throws IllegalArgumentException, NoSuchAlgorithmException {
        String kty = (String) jsonJwk.get("kty");
        if (kty == null) {
            throw new IllegalArgumentException("`kty` must not be null");
        }
        KeySpec ks = null;
        KeyFactory kf = KeyFactory.getInstance(kty);
        switch (kty) {
        case "RSA":
            String nVal = (String) jsonJwk.get("n");
            String eVal = (String) jsonJwk.get("e");
            if (nVal == null || eVal == null) {
                throw new IllegalArgumentException("`RSA` key must contain `n` and `e`.");
            }
            BigInteger n = new BigInteger(1, PluginUtils.decodeBase64Url(nVal));
            BigInteger e = new BigInteger(1, PluginUtils.decodeBase64Url(eVal));
            ks = new RSAPublicKeySpec(n, e);
            break;
        case "EC":
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            String crv = (String) jsonJwk.get("crv");
            if (!"P-256".equals(crv)) {
                throw new IllegalArgumentException(String.format("curve %s is not supported", crv));
            }
            String xVal = (String) jsonJwk.get("x");
            String yVal = (String) jsonJwk.get("y");
            if (xVal == null || yVal == null) {
                throw new IllegalArgumentException("`EC` key must contain `x` and `y`.");
            }
            BigInteger x = new BigInteger(1, PluginUtils.decodeBase64Url(xVal));
            BigInteger y = new BigInteger(1, PluginUtils.decodeBase64Url(yVal));
            ECPoint w = new ECPoint(x, y);
            try {
                params.init(new ECGenParameterSpec("secp256r1"));
                ks = new ECPublicKeySpec(w, params.getParameterSpec(ECParameterSpec.class));
            } catch (NullPointerException | InvalidParameterSpecException ex) {
                throw new IllegalArgumentException("ECGenParameterSpec failed.", ex);
            }
            break;
        default:
            throw new IllegalArgumentException(String.format("kty %s is not supported", kty));
        }

        try {
            return kf.generatePublic(ks);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Generating public key failed", e);
        }
    }
}
