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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
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

import io.personium.plugin.base.auth.AuthPlugin;
import io.personium.plugin.base.auth.AuthPluginException;
import io.personium.plugin.base.auth.AuthPluginLoader;

/**
 * PluginLoader for OIDC authentication.
 */
public class OIDCPluginLoader implements AuthPluginLoader {

    /** Logger. */
    private static Logger log = LoggerFactory.getLogger(OIDCPluginLoader.class);

    /**
     * @{inheritDoc}
     */
    @Override
    public List<AuthPlugin> loadInstances() {
        List<AuthPlugin> result = new ArrayList<AuthPlugin>();
        Properties props = loadProperties();

        Pattern patternKey = Pattern.compile("^io\\.personium\\.plugin\\.oidc\\.(\\w+)\\.enabled$");

        for (Entry<Object, Object> prop : props.entrySet()) {
            String propKey = prop.getKey().toString();
            Matcher matcher = patternKey.matcher(propKey);
            if (matcher.matches()) {
                boolean isEnabled = Boolean.parseBoolean(props.getProperty(propKey));
                if (!isEnabled) {
                    continue;
                }

                String propPrefix = "io.personium.plugin.oidc." + matcher.group(1);
                String configURL = props.getProperty(propPrefix + ".configURL");
                String trustedClientIds = props.getProperty(propPrefix + ".trustedClientIds");

                if (configURL == null) {
                    log.info("configURL of " + matcher.group(1) + "is not set. Skip loading.");
                    continue;
                }
                if (trustedClientIds == null) {
                    log.info("trustedClientIds of " + matcher.group(1) + "is not set. Skip loading");
                    continue;
                }

                List<String> listTrustedClientIds = Arrays.asList(trustedClientIds.split(" "));
                String pluginName = props.getProperty(propPrefix + ".pluginName", "Generic OIDC Plugin");
                String accountType = props.getProperty(propPrefix + ".accountType", "oidc:generic");
                String accountNameKey = props.getProperty(propPrefix + ".accountNameKey", "username");
                String grantType = props.getProperty(propPrefix + ".grantType", "urn:x-personium:oidc:generic");

                try {
                    result.add(new GenericOIDCAuthPlugin(configURL, listTrustedClientIds, pluginName, accountType,
                            accountNameKey, grantType));
                    StringBuilder logSB = new StringBuilder();
                    logSB.append("Loaded plugin: " + pluginName + "\n");
                    logSB.append("  configURL: " + configURL + "\n");
                    logSB.append("  trustedClientIds: " + listTrustedClientIds + "\n");
                    logSB.append("  accountType: " + accountType + "\n");
                    logSB.append("  accountNameKey: " + accountNameKey + "\n");
                    logSB.append("  grantType: " + grantType + "\n");
                    log.info(logSB.toString());
                } catch (AuthPluginException e) {
                    // Ignore exception while initializing auth plugin.
                    log.info("exception is thrown while initializing auth plugin for " + accountType, e);
                }
            }
        }

        return result;
    }

    private Properties loadProperties() {
        Properties props = new Properties();
        String configFilename = System.getProperty("io.personium.configurationFile",
                "personium-unit-config.properties");
        boolean loaded = false;

        // load from classpath
        try (InputStream is = OIDCPluginLoader.class.getClassLoader().getResourceAsStream(configFilename)) {
            if (is != null) {
                log.info("loading properties from classpath: " + configFilename);
                props.load(is);
                loaded = true;
            }
        } catch (IOException e) {
            log.info("IOException while loading: " + configFilename, e);
        }

        // Read the local file specified
        if (!loaded) {
            try (InputStream is = new FileInputStream(configFilename)) {
                log.info("loading properties from local file: " + configFilename);
                props.load(is);
                loaded = true;
            } catch (FileNotFoundException e) {
                log.info("Properties file is not found: " + configFilename, e);
            } catch (IOException e) {
                log.info("IOException while processing: " + configFilename, e);
            }
        }

        if (!loaded) {
            log.info("Properties file cannot be loaded: " + configFilename);
        }
        return props;
    }

}
