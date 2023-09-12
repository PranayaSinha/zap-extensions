package org.zaproxy.addon.TypeJug;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Active scan rule for Type Juggling vulnerabilities in PHP applications.
 * Reference:
 * https://www.owasp.org/index.php/PHP_Type_Juggling
 *
 * @author [Your Name Here]
 */
public class TypeJuggling extends AbstractAppParamPlugin {

    private static final String MESSAGE_PREFIX = "ascanrules.typejuggling.";
    private static final int PLUGIN_ID = 90022;

    private static final String[] TYPE_JUGGLING_PAYLOADS = {
        "0e12345", "0e54321", "0", "1"
    };

    private static final String[] TYPE_JUGGLING_INDICATORS = {
        "Type Juggle Successful",  // Modify this based on possible responses.
        "Type coercion occurred"
    };

    private static final Logger LOGGER = LogManager.getLogger(TypeJuggling.class);

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public void init() {
        // do nothing
    }

    @Override
    public void scan(HttpMessage msg, String paramName, String value) {
        String originalContent = getBaseMsg().getResponseBody().toString();
        String responseContent;

        LOGGER.debug(
                "Checking [{}] [{}], parameter [{}] for Type Juggling vulnerabilities.",
                msg.getRequestHeader().getMethod(),
                msg.getRequestHeader().getURI(),
                paramName);

        for (String payload : TYPE_JUGGLING_PAYLOADS) {
            msg = getNewMsg();
            setParameter(msg, paramName, payload);

            LOGGER.trace("Testing [{}] = [{}]", paramName, payload);

            try {
                sendAndReceive(msg, false);
                responseContent = msg.getResponseBody().toString();

                for (String indicator : TYPE_JUGGLING_INDICATORS) {
                    if (responseContent.contains(indicator)) {
                        if (originalContent.contains(indicator)) {
                            continue;
                        }

                        LOGGER.debug(
                                "[Type Juggling Found] on parameter [{}] with payload [{}]",
                                paramName,
                                payload);

                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setParam(paramName)
                                .setAttack(payload)
                                .setEvidence(indicator)
                                .setMessage(msg)
                                .raise();

                        return;
                    }
                }

            } catch (IOException ex) {
                LOGGER.warn(
                        "Type Juggling check failed for parameter [{}] and payload [{}] due to an I/O error.",
                        paramName,
                        payload,
                        ex);
            }

            if (isStop()) {
                return;
            }
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }
}
