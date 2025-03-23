/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.ssrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"ssrf.hint3"})
public class SSRFTask2 implements AssignmentEndpoint {

  @PostMapping("/SSRF/task2")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    return furBall(url);
  }

  protected AttackResult furBall(String url) {
    URL parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch (MalformedURLException e) {
      return getFailedResult("Invalid URL: " + e.getMessage());
    }

    // Allow only HTTP protocol (No HTTPS or other protocols)
    if (!"http".equalsIgnoreCase(parsedUrl.getProtocol())) {
      return getFailedResult("Only HTTP protocol is allowed");
    }

    // Only allow the specified host (Exact match)
    if (!"ifconfig.pro".equalsIgnoreCase(parsedUrl.getHost())) {
      return getFailedResult("Unauthorized host");
    }
    
    // Allow only default HTTP port (80) or if unspecified (-1)
    int port = parsedUrl.getPort();
    if (port != -1 && port != 80) {
      return getFailedResult("Unauthorized port. Only HTTP port 80 is allowed.");
    }

    HttpURLConnection connection = null;
    try {
      connection = (HttpURLConnection) parsedUrl.openConnection();
      connection.setInstanceFollowRedirects(false); // Prevent redirects to avoid bypasses
      connection.setConnectTimeout(5000); // Timeout for connecting
      connection.setReadTimeout(5000);    // Timeout for reading data
      connection.connect();
      
      int status = connection.getResponseCode();
      if (status >= 300 && status < 400) {
        return getFailedResult("Redirections are not allowed");
      }
      
      try (InputStream in = connection.getInputStream()) {
        String html = new String(in.readAllBytes(), StandardCharsets.UTF_8)
                        .replaceAll("\n", "<br>");
        return success(this).feedback("ssrf.success").output(html).build();
      }
    } catch (IOException e) {
      String errorMsg = "Error fetching URL: " + e.getMessage();
      return getFailedResult(errorMsg);
    } finally {
      if (connection != null) {
        connection.disconnect();
      }
    }
  }

  private AttackResult getFailedResult(String errorMsg) {
    return failed(this).feedback("ssrf.failure").output(errorMsg).build();
  }
}
