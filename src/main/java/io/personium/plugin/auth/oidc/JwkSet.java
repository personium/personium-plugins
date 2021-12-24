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
import java.util.ArrayList;
import java.util.List;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import io.personium.plugin.base.utils.PluginUtils;

/**
 * JSON Web Key Set. Please refer to https://datatracker.ietf.org/doc/html/rfc7517#section-5 .
 */
public class JwkSet {

    /** Key for Keys Parameter. */
    public static final String KEYS = "keys";

    /** List of JSON Web Key. */
    List<JSONObject> listJwks = null;

    /**
     * Constructor of Jwks.
     */
    public JwkSet() {
        this.listJwks = new ArrayList<JSONObject>();
    }

    /**
     * Get keys from document.
     * @return list of Jwk.
     */
    public List<JSONObject> getKeys() {
        return this.listJwks;
    }

    /**
     * Parse JSON to JwkSet.
     * @param jsonJwks source JSON.
     * @return JwkSet.
     */
    public static JwkSet parseJSON(JSONObject jsonJwks) {
        if (jsonJwks == null) {
            throw new IllegalArgumentException("jsonJwks must not be null.");
        }
        Object objKeys = jsonJwks.get(KEYS);
        if (!(objKeys instanceof JSONArray)) {
            throw new IllegalArgumentException("jsonJwks must contain JSONArray in `keys`.");
        }

        JSONArray arrKeys = (JSONArray) objKeys;
        JwkSet result = new JwkSet();
        for (Object objKey : arrKeys) {
            if (!(objKey instanceof JSONObject)) {
                continue;
            }
            result.listJwks.add((JSONObject) objKey);
        }
        return result;
    }

    /**
     * fetch Jwks from jwksURI.
     * @param jwksURI source URI.
     * @return JwkSet.
     * @throws IOException thrown if Exception is happened while fetching
     * @throws ParseException thrown if Exception is happened while parsing
     */
    public static JwkSet fetchJwks(String jwksURI) throws IOException, ParseException {
        JSONObject jsonJwks = PluginUtils.getHttpJSON(jwksURI);
        return JwkSet.parseJSON(jsonJwks);
    }
}
