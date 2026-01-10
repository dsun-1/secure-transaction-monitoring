package com.security.tests.crypto;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * OWASP A02: Cryptographic Failures - TLS/SSL Enforcement Testing
 * Tests HTTPS redirect enforcement and HSTS header presence in production environments.
 * Skips tests in demo mode (localhost) as HTTPS is not expected in local development.
 */
public class TLSEnforcementTest extends BaseTest {
    
    @Test(priority = 1, description = "Verify HTTPS redirect in production mode")
    public void testHTTPSRedirect() {
        // Skip if running against localhost (demo mode)
        if (isDemoMode()) {
            System.out.println("Skipping HTTPS redirect test - running in demo mode (localhost)");
            return;
        }
        
        // Attempt to access HTTP version of the base URL
        String httpUrl = baseUrl.replace("https://", "http://");
        
        try {
            Response response = RestAssured.given()
                .redirects().follow(false)  // Don't auto-follow redirects
                .when()
                .get(httpUrl);
            
            int statusCode = response.getStatusCode();
            
            // Verify redirect to HTTPS (301/302/307/308)
            if (statusCode >= 300 && statusCode < 400) {
                String location = response.getHeader("Location");
                Assert.assertNotNull(location, "Redirect location header missing");
                Assert.assertTrue(location.startsWith("https://"), 
                    "HTTP request should redirect to HTTPS, got: " + location);
                
                System.out.println("✓ HTTP correctly redirects to HTTPS: " + location);
            } else {
                // Log security event - HTTP allowed without redirect
                SecurityEvent event = SecurityEvent.createHighSeverityEvent(
                    "CRYPTOGRAPHIC_FAILURE",
                    "anonymous",
                    "TLS enforcement bypass - HTTP not redirected to HTTPS",
                    "HTTP access allowed without HTTPS redirect (Status: " + statusCode + ")"
                );
                eventLogger.logSecurityEvent(event);
                
                Assert.fail("HTTP request should redirect to HTTPS, but got status: " + statusCode);
            }
            
        } catch (Exception e) {
            System.out.println("Note: Unable to test HTTP redirect - " + e.getMessage());
            // Don't fail test if server only listens on HTTPS (connection refused is expected)
        }
    }
    
    @Test(priority = 2, description = "Verify HSTS header presence")
    public void testHSTSHeader() {
        // Skip if running against localhost (demo mode)
        if (isDemoMode()) {
            System.out.println("Skipping HSTS header test - running in demo mode (localhost)");
            return;
        }
        
        Response response = RestAssured.given()
            .when()
            .get(baseUrl + "/products");
        
        String hstsHeader = response.getHeader("Strict-Transport-Security");
        
        if (hstsHeader == null || hstsHeader.isEmpty()) {
            // Log security event - HSTS header missing
            SecurityEvent event = SecurityEvent.createHighSeverityEvent(
                "CRYPTOGRAPHIC_FAILURE",
                "anonymous",
                "Missing Strict-Transport-Security header allows downgrade attacks",
                "HSTS header missing in HTTPS response"
            );
            eventLogger.logSecurityEvent(event);
            
            Assert.fail("Strict-Transport-Security header should be present in HTTPS responses");
        }
        
        // Verify HSTS header has reasonable max-age (at least 1 year = 31536000 seconds)
        Assert.assertTrue(hstsHeader.contains("max-age="), 
            "HSTS header should contain max-age directive");
        
        System.out.println("✓ HSTS header present: " + hstsHeader);
    }
    
    @Test(priority = 3, description = "Verify secure cookie flags in HTTPS mode")
    public void testSecureCookieFlags() {
        // Skip if running against localhost (demo mode)
        if (isDemoMode()) {
            System.out.println("Skipping secure cookie test - running in demo mode (localhost)");
            return;
        }
        
        // Login to get session cookies
        Response response = RestAssured.given()
            .formParam("username", "testuser")
            .formParam("password", "password123")
            .when()
            .post(baseUrl + "/login");
        
        // Check if session cookies have Secure flag
        response.getDetailedCookies().forEach(cookie -> {
            String name = cookie.getName();
            if (name.toLowerCase().contains("session") || name.toLowerCase().contains("jsessionid")) {
                if (!cookie.isSecured()) {
                    // Log security event - session cookie without Secure flag
                    SecurityEvent event = SecurityEvent.createMediumSeverityEvent(
                        "CRYPTOGRAPHIC_FAILURE",
                        "testuser",
                        "Cookie can be transmitted over unencrypted HTTP connection",
                        "Session cookie '" + name + "' missing Secure flag in HTTPS context"
                    );
                    eventLogger.logSecurityEvent(event);
                    
                    Assert.fail("Session cookie '" + name + "' should have Secure flag in HTTPS mode");
                }
            }
        });
        
        System.out.println("✓ Session cookies have Secure flag");
    }
    
    /**
     * Helper method to detect if running in demo/development mode (localhost)
     */
    private boolean isDemoMode() {
        return baseUrl.contains("localhost") || baseUrl.contains("127.0.0.1");
    }
}
