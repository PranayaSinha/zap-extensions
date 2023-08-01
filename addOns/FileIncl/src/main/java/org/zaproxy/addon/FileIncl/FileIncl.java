package org.zaproxy.zap.extension.FileIncl;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;

public class FileIncl extends AbstractAppParamPlugin {

    private static final Map<String, String> ALERT_TAGS = new HashMap<String, String>() {
        {
            put("OWASP 2021 A04", "Insecure Direct Object References");
            put("OWASP 2017 A05", "Security Misconfiguration");
        }
    };

    private static final Logger LOGGER = LogManager.getLogger(FileIncl.class);

    @Override
    public int getId() {
        return 20015; // update as necessary
    }

    @Override
    public String getName() {
        return "File Inclusion - Pranaya";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("FileInclusionPol.desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("FileInclusionPol.sol");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("FileInclusionPol.extrainfo");
    }

    /**
     * Scans the params for file inclusion vulnerabilities.
     */
    @Override
    public void scan(HttpMessage msg, String param, String value) {
        String attack = "../etc/passwd"; // this is a common file to try and include, but you could also try others

        TreeSet<HtmlParameter> params = msg.getFormParams();

        if (params.contains(new HtmlParameter(HtmlParameter.Type.form, param, value))) {
            // add another param with the same name
            params.add(new HtmlParameter(HtmlParameter.Type.form, param, attack));

            msg.setFormParams(params);

            try {
                sendAndReceive(msg);
                if (msg.getResponseBody().toString().contains("ok")) {
                    // we found evidence of file inclusion vulnerability
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setParam(param)
                            .setMessage(msg)
                            .raise();
                }
            } catch (Exception e) {
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
        return 22; // CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
    }

    @Override
    public int getWascId() {
        return 33; // WASC-33: Path Traversal
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
