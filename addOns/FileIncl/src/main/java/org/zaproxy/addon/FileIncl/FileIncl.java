package org.zaproxy.addon.FileIncl;

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

public class FileIncl extends AbstractAppPlugin {

    private static final Logger LOGGER = LogManager.getLogger(FileIncl.class);

    @Override
    public int getId() {
        return 60100046; // This should be unique across all active and passive rules
    }

    @Override
    public String getName() {
        return "File Inclusion Vulnerability Check";
    }

    @Override
    public String getDescription() {
        return "Checks for file inclusion vulnerabilities by substituting file names in URL parameters.";
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return "Ensure proper access controls are in place for sensitive files. " + 
            "Do not allow user-supplied input to dictate file paths without proper validation and sanitization.";
    }

    @Override
    public String getReference() {
        return "https://owasp.org/www-community/attacks/Path_Traversal";
    }

    @Override
    public void scan() {
        HttpMessage msg = getBaseMsg();
        String[] fileNames = {"file1.php", "file2.php", "file3.php", "file4.php",
                                "../../../../etc/passwd",
                                "../../../../etc/shadow",
                                "../../../../etc/group",
                                "../../../../etc/hosts",
                                "../../../../../../etc/passwd"};  
        for (String fileName : fileNames) {
            try {
                // Clone the original message
                HttpMessage testMsg = msg.cloneRequest();

                // Set new file name in the request parameter
                String query = msg.getRequestHeader().getURI().getQuery();
                query = query.replaceFirst("file1.php", fileName);
                testMsg.getRequestHeader().getURI().setQuery(query);

                // Send the request and receive the response
                sendAndReceive(testMsg);

                // Check the response to see if it contains any evidence of the file inclusion.
                int responseCode = testMsg.getResponseHeader().getStatusCode();
                String responseBody = testMsg.getResponseBody().toString();

                if (responseCode == 200 && !responseBody.contains("Failed")) {
                    newAlert()
                        .setRisk(Alert.RISK_HIGH)
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setName("Potential File Inclusion")
                        .setDescription("The path with " + fileName + " appears to expose sensitive data.")
                        .setSolution("Ensure proper access controls are in place for this file.")
                        .setEvidence(responseBody)
                        //.setCweId(22) // CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
                        //.setWascId(33) // WASC-33: Path Traversal
                        .setMessage(testMsg)
                        .raise();
                    // return; 
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
        return 22;
    }

    @Override
    public int getWascId() {
        return 33;
    }
}
