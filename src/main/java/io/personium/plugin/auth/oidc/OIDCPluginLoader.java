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
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.personium.plugin.base.PluginLog;
import io.personium.plugin.base.auth.AuthPlugin;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.auth.AuthPluginLoader;

/**
 * PluginLoader for OIDC authentication
 */
public class OIDCPluginLoader implements AuthPluginLoader {

    /** Logger */
    private static Logger log = LoggerFactory.getLogger(OIDCPluginLoader.class);

    /**
     * @{inheritDoc}
     */
    @Override
    public ArrayList<AuthPlugin> loadInstances() {
        ArrayList<AuthPlugin> result = new ArrayList<AuthPlugin>();
        Properties props = new Properties();

        String unitConfigFilename = System.getProperty("io.personium.configurationFile", "personium-unit-config.properties");

        try (InputStream is = ClassLoader.getSystemResourceAsStream(unitConfigFilename)) {
            if (is == null) {
                // file not found
                log.info("configurationFile is not found: " + unitConfigFilename);
                return result;
            }
            props.load(is);
        } catch(IllegalArgumentException | IOException e) {
            e.printStackTrace();
        }

        Pattern patternKey = Pattern.compile("io.personium.plugin.oidc.(\\w+).enabled");

        for (Entry<Object, Object> prop : props.entrySet()) {
            String propKey = prop.getKey().toString();
            Matcher matcher = patternKey.matcher(propKey);
            if (matcher.matches()) {
                boolean isEnabled = Boolean.parseBoolean(props.getProperty(propKey));
                if (!isEnabled) continue;

                String propPrefix = "io.personium.plugin.oidc." + matcher.group(1);
                String CONFIGURATION_ENDPOINT = props.getProperty(propPrefix + ".configURL");
                String trustedClientIds = props.getProperty(propPrefix + ".trustedClientIds");
                List<String> TRUSTED_CLIENT_IDS = Arrays.asList(trustedClientIds.split(" "));

                String CUSTOM_PLUGIN_NAME = props.getProperty(propPrefix + ".pluginName", "Generic OIDC Plugin");
                String CUSTOM_ACCOUNT_TYPE = props.getProperty(propPrefix + ".accountType", "oidc:generic");
                String CUSTOM_ACCOUNT_NAME_KEY = props.getProperty(propPrefix + ".accountNameKey", "username");
                String CUSTOM_GRANT_TYPE = props.getProperty(propPrefix + ".grantType", "urn:x-personium:oidc:generic");

                try {
                    result.add(new GenericOIDCAuthPlugin(CONFIGURATION_ENDPOINT,
                        TRUSTED_CLIENT_IDS,
                        CUSTOM_PLUGIN_NAME,
                        CUSTOM_ACCOUNT_TYPE,
                        CUSTOM_ACCOUNT_NAME_KEY,
                        CUSTOM_GRANT_TYPE));
                } catch (AuthPluginException e) {
                    // Ignore exception while initializing auth plugin.
                    log.info("exception is thrown while initializing auth plugin for " + CUSTOM_ACCOUNT_TYPE);
                }
            }
        }

        return result;
    }
}
