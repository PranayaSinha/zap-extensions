package org.zaproxy.zap.extension.HTTParamPol;

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
import org.apache.commons.httpclient.URIException;

public class HttpParamPol extends AbstractAppParamPlugin {

    private static final Map<String, String> ALERT_TAGS = new HashMap<String, String>() {
        {
            put("OWASP 2021 A03", "Injection");
            put("OWASP 2017 A01", "Injection");
            put("WSTG V42 INPV 04", "Param Pollution");
        }
    };

    private static final Logger LOGGER = LogManager.getLogger(HttpParamPol.class);

    @Override
    public int getId() {
        return 20014;
    }

    @Override
    public String getName() {
        return "Http Param Pollution - Pranaya";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("HTTPParamPoll.desc");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString("HTTPParamPoll.sol");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("HTTPParamPoll.extrainfo");
    }

    /**
     * Scans the params for HTTP parameter pollution.
     */
       /**
     * Scans the params for HTTP parameter pollution.
     */
    @Override
    public void scan(HttpMessage msg, String param, String value) {
        TreeSet<HtmlParameter> originalParams;
        boolean isQueryParam = false;

        if ("search".equals(param) || "user".equals(param)) {
            // Extract the query parameters from the request URI
            String query = msg.getRequestHeader().getURI().getEscapedQuery();
            if (query != null) {
                originalParams = new TreeSet<>();
                for (String paramValue : query.split("&")) {
                    String[] parts = paramValue.split("=", 2);
                    if (parts.length == 2) {
                        originalParams.add(new HtmlParameter(HtmlParameter.Type.url, parts[0], parts[1]));
                    }
                }
            } else {
                originalParams = new TreeSet<>();
            }
            isQueryParam = true;
        } else {
            originalParams = msg.getFormParams();
        }

        if (originalParams.contains(new HtmlParameter(HtmlParameter.Type.url, param, value))) {
            // add another param with the same name
            originalParams.add(new HtmlParameter(HtmlParameter.Type.url, param, value + "dhaskjdhaskjdh"));

            if (isQueryParam) {
                // Reconstruct the query string with the modified parameters
                StringBuilder sb = new StringBuilder();
                for (HtmlParameter p : originalParams) {
                    if (sb.length() > 0) {
                        sb.append('&');
                    }
                    sb.append(p.getName()).append('=').append(p.getValue());
                }
                try {
                    msg.getRequestHeader().getURI().setEscapedQuery(sb.toString());
                } catch (URIException e) {
                    LOGGER.error(e.getMessage(), e);
                }
            } else {
                msg.setFormParams(originalParams);
            }

            try {
                sendAndReceive(msg);
                if (msg.getResponseBody().toString().contains("No results found ")) {
                    // we found evidence of HTTP parameter pollution
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
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        return 20; // CWE-20: Improper Input Validation
    }

    @Override
    public int getWascId() {
        return 20; // WASC-20: Improper Input Handling
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}