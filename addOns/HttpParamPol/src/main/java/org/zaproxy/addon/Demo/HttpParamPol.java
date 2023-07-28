package org.zaproxy.zap.extension.HTTParamPol;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;
//import org.zaproxy.addon.commonlib.CommonAlertTag;

public class HttpParamPol extends AbstractAppParamPlugin {

    // private static final Map<String, String> ALERT_TAGS =
    //         CommonAlertTag.toMap(
    //                 CommonAlertTag.OWASP_2021_A03_INJECTION,
    //                 CommonAlertTag.OWASP_2017_A01_INJECTION,
    //                 CommonAlertTag.WSTG_V42_INPV_04_PARAM_POLLUTION);

    private static final Logger LOGGER = LogManager.getLogger(HttpParamPol.class);

    @Override
    public int getId() {
        return 20014;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("HTTPParamPoll.name");
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
        return Constant.messages.getString("ascanbeta.HTTPParamPoll.sol");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString("ascanbeta.HTTPParamPoll.extrainfo");
    }

    /**
     * Scans the params for HTTP parameter pollution.
     */
    @Override
    public void scan(HttpMessage msg, String param, String value) {

        TreeSet<HtmlParameter> originalParams = msg.getFormParams();
        if (originalParams.contains(new HtmlParameter(HtmlParameter.Type.form, param, value))) {
            // add another param with the same name
            originalParams.add(new HtmlParameter(HtmlParameter.Type.form, param, value + "%26zap%3Dzaproxy"));

            msg.setFormParams(originalParams);

            try {
                sendAndReceive(msg);
                if (msg.getResponseBody().toString().contains(value + "%26zap%3Dzaproxy")) {
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
    
    // @Override
    // public Map<String, String> getAlertTags() {
    //     return ALERT_TAGS;
    // }
}
