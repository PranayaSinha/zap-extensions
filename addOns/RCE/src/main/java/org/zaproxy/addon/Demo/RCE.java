package org.zaproxy.addon.rce;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;

public class RCE extends AbstractAppParamPlugin {
  
  private static final Logger log = LogManager.getLogger(RCE.class);
  private static final String NAME = "RCE Scan";
  private static final String DESCRIPTION = "Scans for general Remote Code Execution vulnerabilities.";

  // Include more alert tags as per your requirement
  private static final Map<String, String> ALERT_TAGS =
      CommonAlertTag.toMap(CommonAlertTag.OWASP_2021_A01_INJECTION);

  private List<String> payloads;

  @Override
  public int getId() {
    return 102; // ID should be unique across all active scan rules
  }

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public String getDescription() {
    return DESCRIPTION;
  }

  // Initialize other properties, risk levels, and configurations
  
  @Override
  public void init() {
    // Load payloads from file
    payloads = new ArrayList<>();
    loadPayloads("command_exec.txt");
    loadPayloads("command-execution-unix.txt");
  }

  private void loadPayloads(String fileName) {
    try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
      String line;
      while ((line = br.readLine()) != null) {
        payloads.add(line.trim());
      }
    } catch (IOException e) {
      log.error("Error loading payloads from " + fileName, e);
    }
  }

  @Override
  public void scan(final HttpMessage msg, final String param, final String value) {
    for (String payload : payloads) {
      try {
        HttpMessage newMsg = getNewMsg();
        setParameter(newMsg, param, payload);
        sendAndReceive(newMsg);

        if (isRceVulnerable(newMsg)) {
          Alert alert = new Alert(getId(), getRisk(), Alert.CONFIDENCE_MEDIUM, getName());
          // Set more alert properties, e.g. alert.setEvidence, alert.setMessage, etc.
          // Use the alert to report the vulnerability
          bingo(alert.getRisk(), alert.getConfidence(), alert.getName(), alert.getDescription(),
                null, 
                param, 
                payload, 
                "", 
                alert.getSolution(), alert.getReference(), alert.getEvidence(), 
                537, 
                20, 
                newMsg);
          //return;
        }
      } catch (Exception e) {
        log.error(e.getMessage(), e);
      }
    }
  }

  private boolean isRceVulnerable(HttpMessage msg) {
    String responseBody = msg.getResponseBody().toString();

    List<String> rceIndicators = Arrays.asList(
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/bin/sh",
        "bin:x:2:2:bin:/bin:/bin/sh",
        "sys:x:3:3:sys:/dev:/bin/sh",
        "Linux crashlab 4.4.X-XX-generic #72-Ubuntu",
        "whoami",
        "real	0m5.007s",
        "real	0m0.002s",
        "dnsbin.zhack.ca",
        "http://dnsbin.zhack.ca/",
        "child_process"
    );
    
    for(String indicator: rceIndicators) {
        if(responseBody.contains(indicator)) {
            return true;
        }
    }
    return false;
}


  @Override
  public Map<String, String> getAlertTags() {
    return ALERT_TAGS;
  }
}

