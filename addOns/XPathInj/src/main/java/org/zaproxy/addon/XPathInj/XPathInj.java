package org.zaproxy.addon.XPathInj;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
//import org.zaproxy.addon.commonlib.CommonAlertTag;
import java.io.IOException;

public class XPathInj extends AbstractAppParamPlugin {

    private static final Logger log = LogManager.getLogger(XPathInj.class);

    private static final String[] XPATH_PAYLOADS = {
        "' or '1'='1",
        "' or ''='",
        "x' or 1=1 or 'x'='y",
        "/",
        "//",
        "//*",
        "*/*",
        "@*",
        "count(/child::node())",
        "x' or name()='username' or 'x'='y",
        "' and count(/*)=1 and '1'='1",
        "' and count(/@*)=1 and '1'='1",
        "' and count(/comment())=1 and '1'='1",
        "search=')] | //user/*[contains(*,'",
        "search=Har') and contains(../password,'c",
        "search=Har') and starts-with(../password,'c"

    };

    private static final String[] XPATH_ERRORS = {
        "secret",
        "logged in",
        "result",
        "key",
        "XPathException",
        "MS.Internal.Xml.",
        "Unknown error in XPath",
        "org.apache.xpath.XPath",
        "A closing bracket expected in",
        "An operand in Union Expression does not produce a node-set",
        "Cannot convert expression to a number",
        "Document Axis does not allow any context Location Steps",
        "Empty Path Expression",
        "Empty Relative Location Path",
        "Empty Union Expression",
        "Expected ')' in",
        "Expected node test or name specification after axis operator",
        "Incompatible XPath key",
        "Incorrect Variable Binding",
        "libxml2 library function failed",
        "libxml2",
        "xmlsec library function",
        "xmlsec",
        "error '80004005'",
        "A document must contain exactly one root element.",
        "<font face=\"Arial\" size=2>Expression must evaluate to a node-set.",
        "Expected token '\\]'",
        "<p>msxml4.dll</font>",
        "<p>msxml3.dll</font>",
        // Lotus notes error when document searching inside nsf files
        "4005 Notes error: Query is not understandable",
        // PHP error
        "SimpleXMLElement::xpath()",
        "xmlXPathEval: evaluation failed",
        "Expression must evaluate to a node-set."
    };

    private static final Map<String, String> ALERT_TAGS;
    
    static {
        ALERT_TAGS = new HashMap<>();
        ALERT_TAGS.put("OWASP_2021_A06_VULN_COMP", "OWASP 2021: Vulnerable and Outdated Components");
        ALERT_TAGS.put("OWASP_2017_A09_VULN_COMP", "OWASP 2017: Using Components with Known Vulnerabilities");
    }

    @Override
    public int getId() {
        return 102;
    }

    @Override
    public String getName() {
        return "Pranaya: XPath Injection Scan";
    }

    @Override
    public String getDescription() {
        return "XPath Injection allows attackers to inject XPath query/command which can be executed by the application. A successful exploitation can lead to unauthorized access, data retrieval or even in some cases, remote code execution.";
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return "Avoid building XPath queries by string concatenation with untrusted data. Use parameterized queries or APIs that support them. Properly validate and sanitize the input data.";
    }

    @Override
    public String getReference() {
        return "https://www.owasp.org/index.php/XPATH_Injection";
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 643; // CWE-ID for XPath Injection
    }

    @Override
    public int getWascId() {
        return 23; // Web Application Security Consortium ID for XPath Injection
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public void scan(final HttpMessage msg, final String param, final String value) {
        String originalContent = getBaseMsg().getResponseBody().toString();
        for (String attackPattern : XPATH_PAYLOADS) {
            try {
                HttpMessage newMsg = msg.cloneRequest();
                this.setParameter(newMsg, param, attackPattern);
                sendAndReceive(newMsg);
                String responseContent = newMsg.getResponseBody().toString();
                for (String errorString : XPATH_ERRORS) {
                    if (responseContent.toLowerCase().contains(errorString.toLowerCase()) && !originalContent.toLowerCase().contains(errorString.toLowerCase())) {
                        raiseAlert(param, attackPattern, newMsg, errorString);
                        return;  
                    }
                }
            } catch (IOException ex) {
                log.warn(
                        "XPath Injection vulnerability check failed for parameter [{}] and payload [{}] due to an I/O error.",
                        param,
                        attackPattern,
                        ex);
            }
        }
    }

    private void raiseAlert(String param, String attack, HttpMessage msg, String evidence) {
        newAlert()
            .setRisk(Alert.RISK_HIGH)
            .setConfidence(Alert.CONFIDENCE_HIGH)  
            .setDescription(getDescription())
            .setParam(param)
            .setAttack(attack)
            .setEvidence(evidence)
            .setMessage(msg)
            .raise();
    }
}
