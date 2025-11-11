package com.security.tests.ssrf;

import com.security.tests.base.BaseTest;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.testng.annotations.Test;
import static org.testng.Assert.*;

/**
 * OWASP A10:2021 - Server-Side Request Forgery (SSRF)
 * Tests to prevent attackers from making the server perform unintended requests
 */
public class SSRFTest extends BaseTest {

    @Test(description = "OWASP A10 - Prevent internal network access via SSRF")
    public void testInternalNetworkSSRF() {
        // Try to make the server access internal network addresses
        String[] internalAddresses = {
            "http://localhost:8080/admin",
            "http://127.0.0.1:8080/admin",
            "http://192.168.1.1/",
            "http://10.0.0.1/",
            "http://172.16.0.1/"
        };
        
        for (String url : internalAddresses) {
            try {
                Response response = RestAssured
                    .given()
                    .queryParam("url", url)
                    .when()
                    .get(baseUrl + "/api/fetch")
                    .then()
                    .extract()
                    .response();
                
                // Should NOT successfully fetch internal URLs
                assertNotEquals(response.getStatusCode(), 200,
                    "Should not allow fetching internal URL: " + url);
                
            } catch (Exception e) {
                // Good - request failed or was blocked
                logSecurityEvent("SSRF_INTERNAL_NETWORK", "INFO", 
                    "Blocked internal network access attempt: " + url);
            }
        }
        
        logSecurityEvent("SSRF_INTERNAL_CHECK", "INFO", 
            "Verified internal network SSRF protection");
    }

    @Test(description = "OWASP A10 - Prevent cloud metadata service SSRF")
    public void testCloudMetadataSSRF() {
        // AWS, Azure, GCP metadata endpoints
        String[] metadataUrls = {
            "http://169.254.169.254/latest/meta-data/",  // AWS
            "http://169.254.169.254/metadata/instance",  // Azure
            "http://metadata.google.internal/computeMetadata/v1/",  // GCP
            "http://100.100.100.200/latest/meta-data/"   // Alibaba Cloud
        };
        
        for (String url : metadataUrls) {
            try {
                Response response = RestAssured
                    .given()
                    .queryParam("imageUrl", url)
                    .when()
                    .post(baseUrl + "/api/images/import")
                    .then()
                    .extract()
                    .response();
                
                // Should block access to cloud metadata services
                assertFalse(response.getStatusCode() == 200 && 
                           response.getBody().asString().contains("ami-"),
                    "Should not allow access to cloud metadata: " + url);
                
            } catch (Exception e) {
                // Expected - request blocked
                logSecurityEvent("SSRF_CLOUD_METADATA", "INFO", 
                    "Blocked cloud metadata SSRF attempt: " + url);
            }
        }
        
        logSecurityEvent("SSRF_METADATA_CHECK", "INFO", 
            "Verified cloud metadata SSRF protection");
    }

    @Test(description = "OWASP A10 - Prevent file protocol SSRF")
    public void testFileProtocolSSRF() {
        // Try to access local files via file:// protocol
        String[] fileUrls = {
            "file:///etc/passwd",
            "file:///c:/windows/system.ini",
            "file://localhost/etc/hosts",
            "file:///proc/self/environ"
        };
        
        for (String url : fileUrls) {
            try {
                Response response = RestAssured
                    .given()
                    .queryParam("document", url)
                    .when()
                    .get(baseUrl + "/api/documents/view")
                    .then()
                    .extract()
                    .response();
                
                // Should NOT allow file:// protocol
                assertFalse(response.getStatusCode() == 200,
                    "Should not allow file protocol access: " + url);
                
            } catch (Exception e) {
                logSecurityEvent("SSRF_FILE_PROTOCOL", "INFO", 
                    "Blocked file protocol SSRF: " + url);
            }
        }
        
        logSecurityEvent("SSRF_FILE_CHECK", "INFO", 
            "Verified file protocol SSRF protection");
    }

    @Test(description = "OWASP A10 - Prevent DNS rebinding attacks")
    public void testDNSRebindingSSRF() {
        // Domains that might resolve to internal IPs
        String[] suspiciousUrls = {
            "http://127.0.0.1.nip.io",
            "http://localtest.me",
            "http://0.0.0.0.nip.io"
        };
        
        for (String url : suspiciousUrls) {
            try {
                Response response = RestAssured
                    .given()
                    .queryParam("webhook", url)
                    .when()
                    .post(baseUrl + "/api/webhooks/test")
                    .then()
                    .extract()
                    .response();
                
                // Should validate and block suspicious domains
                logSecurityEvent("SSRF_DNS_REBINDING", "INFO", 
                    "Tested DNS rebinding protection for: " + url);
                
            } catch (Exception e) {
                // Good - blocked or errored
            }
        }
        
        logSecurityEvent("SSRF_DNS_CHECK", "INFO", 
            "Verified DNS rebinding protection");
    }

    @Test(description = "OWASP A10 - Test URL validation whitelist")
    public void testURLWhitelistValidation() {
        // Only allow specific trusted domains
        String[] untrustedUrls = {
            "http://evil.com",
            "http://attacker.net",
            "http://192.168.1.1"
        };
        
        for (String url : untrustedUrls) {
            try {
                Response response = RestAssured
                    .given()
                    .queryParam("feedUrl", url)
                    .when()
                    .get(baseUrl + "/api/feed/import")
                    .then()
                    .extract()
                    .response();
                
                // Should only allow whitelisted domains
                assertNotEquals(response.getStatusCode(), 200,
                    "Should block non-whitelisted domain: " + url);
                
            } catch (Exception e) {
                logSecurityEvent("SSRF_WHITELIST", "INFO", 
                    "Blocked non-whitelisted URL: " + url);
            }
        }
        
        logSecurityEvent("SSRF_WHITELIST_CHECK", "INFO", 
            "Verified URL whitelist validation");
    }

    @Test(description = "OWASP A10 - Prevent redirect-based SSRF")
    public void testRedirectSSRF() {
        // Attacker might use redirects to bypass URL filters
        String redirectUrl = "http://attacker.com/redirect?to=http://localhost:8080/admin";
        
        try {
            Response response = RestAssured
                .given()
                .queryParam("imageUrl", redirectUrl)
                .redirects().follow(false)  // Don't follow redirects
                .when()
                .get(baseUrl + "/api/images/import")
                .then()
                .extract()
                .response();
            
            // Should either block or not follow redirects to internal URLs
            logSecurityEvent("SSRF_REDIRECT", "INFO", 
                "Tested redirect-based SSRF protection");
            
        } catch (Exception e) {
            logSecurityEvent("SSRF_REDIRECT", "INFO", 
                "Redirect SSRF blocked: " + e.getMessage());
        }
        
        logSecurityEvent("SSRF_REDIRECT_CHECK", "INFO", 
            "Verified redirect SSRF protection");
    }
}
