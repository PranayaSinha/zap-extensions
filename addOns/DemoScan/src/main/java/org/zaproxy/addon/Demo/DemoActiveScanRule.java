/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.addon.Demo;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * An example active scan rule, for more details see
 * https://www.zaproxy.org/blog/2014-04-30-hacking-zap-4-active-scan-rules/
 *
 * @author psiinon
 */
public class DemoActiveScanRule extends AbstractAppPlugin {

    // wasc_10 is Denial of Service - well, its just an example ;)
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_10");

    private static final Logger LOGGER = LogManager.getLogger(DemoActiveScanRule.class);

    @Override
    public int getId() {
        /*
         * This should be unique across all active and passive rules.
         * The master list is https://github.com/zaproxy/zaproxy/blob/main/docs/scanners.md
         */
        return 60100045;
    }

    @Override
    public String getName() {
        // Strip off the "Example Active Scan Rule: " part if implementing a real one ;)
        // if (vuln != null) {
        //     return "Example Active Scan Rule: " + vuln.getAlert();
        // }
        return "Pranaya Sinha: Demo Active Scan Rule";
    }

    // @Override
    // public boolean targets(
    //         TechSet technologies) { // This method allows the programmer or user to restrict when
    // a
    //     // scanner is run based on the technologies selected.  For example, to restrict the
    // scanner
    //     // to run just when
    //     // C language is selected
    //     return technologies.includes(Tech.C);
    // }

    @Override
    public String getDescription() {
        // if (vuln != null) {
        //     return vuln.getDescription();
        // }
        return "Failed to load vulnerability description from file";
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
        // if (vuln != null) {
        //     return vuln.getSolution();
        // }
        return "Failed to load vulnerability solution from file";
    }

    @Override
    public String getReference() {
        if (vuln != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : vuln.getReferences()) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(ref);
            }
            return sb.toString();
        }
        return "Failed to load vulnerability reference from file";
    }

    /*
     * This method is called by the active scanner for each GET and POST parameter for every page
     * @see org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.paros.network.HttpMessage, java.lang.String, java.lang.String)
     */
    @Override
    public void scan() {
        HttpMessage msg = getBaseMsg();

        // List of possible debug endpoints
        String[] debugEndpoints = {
            "/debug",
            "/_debug",
            "/console",
            "/_console",
            "/status",
            "/_status",
            "/health",
            "/_health",
            "/log",
            "/_log",
            "/trace",
            "/_trace",
            "/info",
            "/_info",
            "/inspect",
            "/_inspect",
            "/monitor",
            "/_monitor",
            "/errors",
            "/_errors",
            "/test",
            "/_test",
            "/dev",
            "/_dev",
            "/development",
            "/_development",
            "/staging",
            "/_staging",
            "/qa",
            "/_qa",
            "/sandbox",
            "/_sandbox",
            "/beta",
            "/_beta",
            "/preview",
            "/_preview"
        };

        for (String endpoint : debugEndpoints) {
            try {
                // Clone the original message
                HttpMessage testMsg = msg.cloneRequest();

                // Change the request path to the possible debug endpoint
                String path = msg.getRequestHeader().getURI().getPath();
                path = path.substring(0, path.lastIndexOf('/') + 1) + endpoint;
                testMsg.getRequestHeader().getURI().setPath(path);

                // Send the request and receive the response
                sendAndReceive(testMsg);

                // Check the response to see if it appears to be a debug endpoint.
                // This could be customized depending on what your debug endpoints return.
                int responseCode = testMsg.getResponseHeader().getStatusCode();
                String responseBody = testMsg.getResponseBody().toString();

                if (responseCode == 200 ) {
                    // We've found a possible debug endpoint
                    newAlert()
                            .setRisk(Alert.RISK_HIGH)
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setName("Possible Debug Endpoint")
                            .setDescription("The path " + path + " appears to be a debug endpoint.")
                            //.setParam(endpoint)
                            .setSolution(
                                    "Disable or protect the debug endpoint before deploying to production.")
                            .setEvidence(responseBody)
                            // .setCweId(
                            //         215) // CWE-215: Information Exposure Through Debug Information
                            // .setWascId(13) // WASC-13: Information Leakage
                            .setMessage(testMsg)
                            .raise();
                    //return;
                }
            } catch (IOException e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        // The CWE id
        return 215;
    }

    @Override
    public int getWascId() {
        // The WASC ID
        return 13;
    }
}
