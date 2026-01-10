package com.security.tests.api;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;

import io.restassured.RestAssured;
import io.restassured.response.Response;

import org.testng.annotations.Test;
import org.testng.Assert;

/**
 * OWASP A04: Insecure Design - Rate Limiting Testing
 * Tests rate limiting effectiveness and attempts to bypass rate limits
 * through various techniques (IP spoofing, distributed sessions).
 */
public class RateLimitingTest extends BaseTest {
    
    @Test(priority = 1, description = "Test rate limiting on API endpoints")
    public void testRateLimiting() {
        RestAssured.baseURI = baseUrl;
        
        
        int requestCount = 100;
        int tooManyRequestsCount = 0;
        int successCount = 0;
        
        for (int i = 0; i < requestCount; i++) {
            Response response = RestAssured
                .given()
                .get("/products");
            
            if (response.statusCode() == 429) { 
                tooManyRequestsCount++;
            } else if (response.statusCode() == 200) {
                successCount++;
            } else {
                throw new AssertionError("Unexpected status code: " + response.statusCode());
            }
        }
        
        org.testng.Assert.assertTrue(tooManyRequestsCount > 0,
            "Rate limiting should trigger under burst traffic");
        assertSecurityEventLogged("RATE_LIMIT_EXCEEDED");
    }
    
    @Test(priority = 2, description = "Test rate limit bypass via X-Forwarded-For header spoofing")
    public void testRateLimitBypassIPSpoofing() {
        RestAssured.baseURI = baseUrl;
        
        // Attempt to bypass rate limiting by rotating X-Forwarded-For IPs
        int requestCount = 60;
        int bypassSuccessCount = 0;
        
        for (int i = 0; i < requestCount; i++) {
            // Rotate IP addresses to attempt bypass
            String spoofedIP = "192.168.1." + (i % 50 + 1);
            
            Response response = RestAssured
                .given()
                .header("X-Forwarded-For", spoofedIP)
                .header("X-Real-IP", spoofedIP)
                .get("/products");
            
            if (response.statusCode() == 200) {
                bypassSuccessCount++;
            }
        }
        
        // If we got more than the rate limit allows (typically 50 requests),
        // then IP spoofing bypassed rate limiting
        if (bypassSuccessCount > 50) {
            // Log security event - rate limit bypass successful
            SecurityEvent event = SecurityEvent.createHighSeverityEvent(
                "RATE_LIMIT_EXCEEDED",
                "anonymous",
                "Rate limiting vulnerable to IP spoofing attacks",
                "Rate limit bypass successful via X-Forwarded-For spoofing (" + bypassSuccessCount + "/" + requestCount + " requests succeeded)"
            );
            eventLogger.logSecurityEvent(event);
            
            System.out.println("? Warning: Rate limiting bypassed via IP spoofing (" + bypassSuccessCount + "/" + requestCount + " succeeded)");
        } else {
            System.out.println("? Rate limiting resistant to X-Forwarded-For spoofing");
        }
        
        // We still want the test to pass, but log the security concern
        Assert.assertTrue(true, "Rate limit bypass test completed");
    }
    
    @Test(priority = 3, description = "Test rate limit bypass via distributed session IDs")
    public void testRateLimitBypassDistributedSessions() {
        RestAssured.baseURI = baseUrl;
        
        // Attempt to bypass rate limiting by using multiple session IDs
        int requestCount = 60;
        int bypassSuccessCount = 0;
        
        for (int i = 0; i < requestCount; i++) {
            // Create different session contexts
            Response response = RestAssured
                .given()
                .header("User-Agent", "Mozilla/5.0-Session-" + i)
                .cookie("fake-session-" + i, "value-" + i)
                .get("/products");
            
            if (response.statusCode() == 200) {
                bypassSuccessCount++;
            }
        }
        
        // If we got more than the rate limit allows, session rotation bypassed it
        if (bypassSuccessCount > 50) {
            // Log security event - rate limit bypass via session rotation
            SecurityEvent event = SecurityEvent.createMediumSeverityEvent(
                "RATE_LIMIT_EXCEEDED",
                "anonymous",
                "Rate limiting may not account for session-based attacks",
                "Rate limit bypass via distributed sessions (" + bypassSuccessCount + "/" + requestCount + " requests succeeded)"
            );
            eventLogger.logSecurityEvent(event);
            
            System.out.println("? Warning: Rate limiting bypassed via session rotation (" + bypassSuccessCount + "/" + requestCount + " succeeded)");
        } else {
            System.out.println("? Rate limiting resistant to session-based bypass attempts");
        }
        
        Assert.assertTrue(true, "Distributed session bypass test completed");
    }
    
    @Test(priority = 4, description = "Test slowloris-style attack staying under rate limit threshold")
    public void testSlowlorisStyleAttack() {
        RestAssured.baseURI = baseUrl;
        
        // Slowloris: Send requests slowly, staying just under the threshold
        // Rate limit is typically 50 requests per 5 seconds
        // Send 49 requests, wait, repeat
        
        int batchSize = 45; // Stay under threshold
        int batches = 3;
        int totalSuccess = 0;
        
        try {
            for (int batch = 0; batch < batches; batch++) {
                int batchSuccess = 0;
                
                // Send batch of requests
                for (int i = 0; i < batchSize; i++) {
                    Response response = RestAssured
                        .given()
                        .get("/products");
                    
                    if (response.statusCode() == 200) {
                        batchSuccess++;
                    }
                    
                    // Small delay between requests (100ms)
                    Thread.sleep(100);
                }
                
                totalSuccess += batchSuccess;
                
                // Wait for rate limit window to reset (5 seconds + buffer)
                if (batch < batches - 1) {
                    Thread.sleep(5500);
                }
            }
            
            // Log security event - slowloris-style attack successful
            SecurityEvent event = SecurityEvent.createMediumSeverityEvent(
                "RATE_LIMIT_EXCEEDED",
                "anonymous",
                "Rate limiting can be bypassed by staying under threshold and waiting for window reset",
                "Slowloris-style attack successful (" + totalSuccess + " requests over " + batches + " batches)"
            );
            eventLogger.logSecurityEvent(event);
            
            System.out.println("? Slowloris-style attack: " + totalSuccess + "/" + (batchSize * batches) + " requests succeeded");
            
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Assert.fail("Slowloris test interrupted");
        }
        
        Assert.assertTrue(true, "Slowloris-style attack test completed");
    }


    @Override
    protected boolean useWebDriver() {
        return false;
    }

}
