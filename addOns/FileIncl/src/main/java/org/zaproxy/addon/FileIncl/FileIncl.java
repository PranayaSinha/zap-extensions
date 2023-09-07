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
        String[][] payloads = {
            {
                "BSD File Inclusion",
                "Ensure proper access controls are in place for sensitive files. " + 
                    "Do not allow user-supplied input to dictate file paths without proper validation and sanitization.",
                "file1.php", "file2.php", "file3.php", "file4.php",
                "../../../../etc/passwd",
                "../../../../etc/shadow",
                "../../../../etc/group",
                "../../../../etc/hosts",
                "../../../../../../etc/passwd"
            },
            {
                "Linux File Inclusion",
                "Ensure proper access controls are in place for sensitive files. " + 
                    "Do not allow user-supplied input to dictate file paths without proper validation and sanitization.",
                    "/etc/group\r\n",
                    "/etc/hosts\r\n",
                    "/etc/motd\r\n",
                    "/etc/issue\r\n",
                    "/etc/bashrc\r\n",
                    "/etc/apache2/apache2.conf\r\n",
                    "/etc/apache2/ports.conf\r\n",
                    "/etc/apache2/sites-available/default\r\n",
                    "/etc/httpd/conf/httpd.conf\r\n",
                    "/etc/httpd/conf.d\r\n",
                    "/etc/httpd/logs/access.log\r\n",
                    "/etc/httpd/logs/access_log\r\n",
                    "/etc/httpd/logs/error.log\r\n",
                    "/etc/httpd/logs/error_log\r\n",
                    "/etc/init.d/apache2\r\n",
                    "/etc/mysql/my.cnf\r\n",
                    "/etc/nginx.conf\r\n",
                    "/opt/lampp/logs/access_log\r\n",
                    "/opt/lampp/logs/error_log\r\n",
                    "/opt/lamp/log/access_log\r\n",
                    "/opt/lamp/logs/error_log\r\n",
                    "/proc/self/environ\r\n",
                    "/proc/version\r\n",
                    "/proc/cmdline\r\n",
                    "/proc/mounts\r\n",
                    "/proc/config.gz\r\n",
                    "/root/.bashrc\r\n",
                    "/root/.bash_history\r\n",
                    "/root/.ssh/authorized_keys\r\n",
                    "/root/.ssh/id_rsa\r\n",
                    "/root/.ssh/id_rsa.keystore\r\n",
                    "/root/.ssh/id_rsa.pub\r\n",
                    "/root/.ssh/known_hosts\r\n",
                    "/usr/local/apache/htdocs/index.html\r\n",
                    "/usr/local/apache/conf/httpd.conf\r\n",
                    "/usr/local/apache/conf/extra/httpd-ssl.conf\r\n",
                    "/usr/local/apache/logs/error_log\r\n",
                    "/usr/local/apache/logs/access_log\r\n",
                    "/usr/local/apache/bin/apachectl\r\n",
                    "/usr/local/apache2/htdocs/index.html\r\n",
                    "/usr/local/apache2/conf/httpd.conf\r\n",
                    "/usr/local/apache2/conf/extra/httpd-ssl.conf\r\n",
                    "/usr/local/apache2/logs/error_log\r\n",
                    "/usr/local/apache2/logs/access_log\r\n",
                    "/usr/local/apache2/bin/apachectl\r\n",
                    "/usr/local/etc/nginx/nginx.conf\r\n",
                    "/usr/local/nginx/conf/nginx.conf\r\n",
                    "/var/apache/logs/access_log\r\n",
                    "/var/apache/logs/access.log\r\n",
                    "/var/apache/logs/error_log\r\n",
                    "/var/apache/logs/error.log\r\n",
                    "/var/log/apache/access.log\r\n",
                    "/var/log/apache/access_log\r\n",
                    "/var/log/apache/error.log\r\n",
                    "/var/log/apache/error_log\r\n",
                    "/var/log/httpd/error_log\r\n",
                    "/var/log/httpd/access_log\r\n",
                    "/var/log/nginx/access_log\r\n",
                    "/var/log/nginx/access.log\r\n",
                    "/var/log/nginx/error_log\r\n",
                    "/var/log/nginx/error.log"
            },
            {
                "Web File Paths",
                "Ensure proper access controls are in place for sensitive files. " + 
                    "Do not allow user-supplied input to dictate file paths without proper validation and sanitization.",
                "/robots.txt",
                "/humans.txt",
                "/style.css",
                "/configuration.php",
                "/wp-login.php",
                "/wp-admin.php",
                "/wp-content/plugins",
                "/include/config.php",
                "/inc/config.php",
                "/include/mysql.php",
                "/inc/mysql.php",
                "/sites/defaults/settings.php",
                "/phpmyadmin/changelog.php",
                "/web.config"
            },
            {
                "Linux File Inclusion for File Descriptors",
                "Ensure proper access controls are in place for sensitive files. " + 
                    "Do not allow user-supplied input to dictate file paths without proper validation and sanitization.",
                "/proc/self/cmdline",
                "/proc/self/stat",
                "/proc/self/status",
                "/proc/self/fd/0",
                "/proc/self/fd/1",
                "/proc/self/fd/2",
                "/proc/self/fd/3",
                "/proc/self/fd/4",
                "/proc/self/fd/5",
                "/proc/self/fd/6",
                "/proc/self/fd/7",
                "/proc/self/fd/8",
                "/proc/self/fd/9",
                "/proc/self/fd/10"
            },
            {
                "General File Names",
                "Ensure proper access controls are in place for sensitive files. " + 
                    "Do not allow user-supplied input to dictate file paths without proper validation and sanitization.",
                "file1.php", "file2.php", "file3.php", "file4.php",
                "../../../../etc/passwd",
                "../../../../etc/shadow",
                "../../../../etc/group",
                "../../../../etc/hosts",
                "../../../../../../etc/passwd"
            }
        };
        

        for (String[] payloadGroup : payloads) {
            for (int i = 2; i < payloadGroup.length; i++) {
                try {
                    HttpMessage testMsg = msg.cloneRequest();
                    String query = msg.getRequestHeader().getURI().getQuery();
                    String originalContent = getBaseMsg().getResponseBody().toString();
                    if (query != null && query.contains(payloadGroup[i])) {
                        query = query.replace(payloadGroup[i], payloadGroup[i]);
                        testMsg.getRequestHeader().getURI().setQuery(query);
                        sendAndReceive(testMsg);
                        int responseCode = testMsg.getResponseHeader().getStatusCode();
                        String responseBody = testMsg.getResponseBody().toString();

                        if (responseCode == 200) {
                            boolean isFileIncluded = false;
                            // Indicators of file inclusion 
                            String[] fileIndicators = {
                                "root:",
                                "apache2.conf",
                                "nginx.conf",
                                "robots.txt",
                                "wp-login.php"
                            };
                            String indic = "";

                            for (String indicator : fileIndicators) {
                                if (responseBody.contains(indicator)) {
                                    isFileIncluded = true;
                                    indic = indicator;
                                    break;
                                }
                            }
                        
                            if (isFileIncluded && !originalContent.contains(indic)) {
                                newAlert()
                                    .setRisk(Alert.RISK_HIGH)
                                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                    .setName(payloadGroup[0])
                                    .setDescription("The path with " + payloadGroup[i] + " appears to expose sensitive data.")
                                    .setSolution(payloadGroup[1])
                                    .setEvidence(responseBody)
                                    .setMessage(testMsg)
                                    .raise();
                            }
                        }
                    }
                } catch (IOException e) {
                    LOGGER.error(e.getMessage(), e);
                }
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
