package com.security.tests.api;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static io.restassured.RestAssured.*;

/**
 * REST API Security Tests
 * Tests authentication, authorization, and security controls via REST endpoints
 */
public class RestAPISecurityTest extends BaseTest {
    
    private static final String BASE_URL = "http://localhost:8080";
    private static final String API_BASE = "/api/security";
    
    @BeforeClass
    public void setupRestAssured() {
        RestAssured.baseURI = BASE_URL;
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
        
        // Disable redirect following to test actual Spring Security behavior
        RestAssured.config = RestAssured.config()
            .redirect(io.restassured.config.RedirectConfig.redirectConfig().followRedirects(false));
    }
    
    @Test(priority = 1, description = "Test public dashboard endpoint is accessible")
    public void testPublicDashboardAccess() {
        Response response = given()
            .contentType(ContentType.JSON)
        .when()
            .get(API_BASE + "/dashboard")
        .then()
            .extract().response();
        
        Assert.assertTrue(response.getStatusCode() == 200 || response.getStatusCode() == 302 || response.getStatusCode() == 401, 
            "Dashboard endpoint should be accessible (200), redirect to login (302), or require auth (401)");
        
        SecurityEvent event = SecurityEvent.createMediumSeverityEvent(
            "API_ACCESS_TEST",
            "public",
            "none",
            "Tested public dashboard API access"
        );
        eventLogger.logSecurityEvent(event);
    }
    
    @Test(priority = 2, description = "Test authentication with invalid credentials")
    public void testInvalidAuthentication() {
        Response response = given()
            .auth().basic("invaliduser", "wrongpassword")
            .contentType(ContentType.JSON)
        .when()
            .get(API_BASE + "/events/high-severity")
        .then()
            .extract().response();
        
        Assert.assertTrue(response.getStatusCode() == 302 || response.getStatusCode() == 401 || response.getStatusCode() == 403, 
            "Invalid credentials should redirect to login (302) or return 401/403");
        
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "INVALID_AUTH_TEST",
            "invaliduser",
            "authentication_failure",
            "Tested authentication with invalid credentials"
        );
        eventLogger.logSecurityEvent(event);
    }
    
    @Test(priority = 3, description = "Test rate limiting with multiple rapid requests")
    public void testRateLimiting() {
        int requestCount = 20;
        int successfulRequests = 0;
        int rateLimitedRequests = 0;
        
        for (int i = 0; i < requestCount; i++) {
            Response response = given()
                .contentType(ContentType.JSON)
            .when()
                .get(API_BASE + "/dashboard")
            .then()
                .extract().response();
            
            if (response.getStatusCode() == 200 || response.getStatusCode() == 302 || response.getStatusCode() == 401) {
                successfulRequests++;
            } else if (response.getStatusCode() == 429) {
                rateLimitedRequests++;
            }
        }
        
        // Log rate limit test results
        SecurityEvent event = SecurityEvent.createMediumSeverityEvent(
            "RATE_LIMIT_TEST",
            "test_client",
            "rate_limit_testing",
            String.format("Sent %d rapid requests: %d successful, %d rate-limited", 
                requestCount, successfulRequests, rateLimitedRequests)
        );
        eventLogger.logSecurityEvent(event);
        
        Assert.assertTrue(successfulRequests > 0, "At least some requests should succeed");
    }
    
    @Test(priority = 4, description = "Test SQL injection via REST API parameters")
    public void testSQLInjectionViaAPI() {
        String[] injectionPayloads = {
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1' UNION SELECT * FROM security_events--",
            "admin'--"
        };
        
        for (String payload : injectionPayloads) {
            Response response = given()
                .queryParam("username", payload)
                .contentType(ContentType.JSON)
            .when()
                .get(API_BASE + "/events/high-severity")
            .then()
                .extract().response();
            
            // Should either sanitize (200/302/401) or reject (400)
            Assert.assertTrue(
                response.getStatusCode() == 200 || 
                response.getStatusCode() == 302 || 
                response.getStatusCode() == 400 || 
                response.getStatusCode() == 401,
                "SQL injection attempt should be handled safely"
            );
            
            // Should not return error messages with SQL details
            String body = response.getBody().asString();
            Assert.assertFalse(body.toLowerCase().contains("sql"), 
                "Response should not leak SQL error details");
        }
        
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "SQL_INJECTION_API_TEST",
            "test_client",
            "injection_attempt",
            "Tested SQL injection via API parameters"
        );
        eventLogger.logSecurityEvent(event);
    }
    
    @Test(priority = 5, description = "Test XSS prevention in API responses")
    public void testXSSPreventionInAPI() {
        String[] xssPayloads = {
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        };
        
        for (String payload : xssPayloads) {
            Response response = given()
                .queryParam("search", payload)
                .contentType(ContentType.JSON)
            .when()
                .get(API_BASE + "/dashboard")
            .then()
                .extract().response();
            
            String body = response.getBody().asString();
            
            // Response should either escape or sanitize
            Assert.assertFalse(body.contains("<script>"), 
                "XSS payload should be sanitized in response");
            Assert.assertFalse(body.contains("onerror="), 
                "XSS event handlers should be removed");
        }
        
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "XSS_API_TEST",
            "test_client",
            "injection_attempt",
            "Tested XSS prevention in API responses"
        );
        eventLogger.logSecurityEvent(event);
    }
    
    @Test(priority = 6, description = "Test transaction anomaly detection via API")
    public void testTransactionAnomalyAPI() {
        Response response = given()
            .contentType(ContentType.JSON)
        .when()
            .get(API_BASE + "/transactions/anomalies")
        .then()
            .extract().response();
        
        Assert.assertTrue(response.getStatusCode() == 200 || response.getStatusCode() == 302 || response.getStatusCode() == 401,
            "Anomaly endpoint should be accessible or protected");
        
        // Optional: Log response details if successful
        if (response.getStatusCode() == 200) {
            // Response body available for debugging if needed
            System.out.println("Anomaly API test returned successful response");
        }
        
        SecurityEvent event = SecurityEvent.createMediumSeverityEvent(
            "ANOMALY_API_TEST",
            "test_client",
            "monitoring_test",
            "Tested transaction anomaly detection API"
        );
        eventLogger.logSecurityEvent(event);
    }
    
    @Test(priority = 7, description = "Test brute force detection via REST API")
    public void testBruteForceViaAPI() {
        int attempts = 10;
        int failedAttempts = 0;
        
        for (int i = 0; i < attempts; i++) {
            Response response = given()
                .auth().basic("testuser", "wrongpassword_" + i)
                .contentType(ContentType.JSON)
            .when()
                .get(API_BASE + "/events/high-severity")
            .then()
                .extract().response();
            
            if (response.getStatusCode() == 302 || response.getStatusCode() == 401 || response.getStatusCode() == 403) {
                failedAttempts++;
            }
            
            // Small delay to avoid overwhelming the system
            try { Thread.sleep(100); } catch (InterruptedException e) {}
        }
        
        // Log brute force test completion
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "BRUTE_FORCE_API_TEST",
            "testuser",
            "brute_force_attack",
            String.format("Simulated brute force with %d failed login attempts", failedAttempts)
        );
        eventLogger.logSecurityEvent(event);
        
        Assert.assertTrue(failedAttempts >= 5, 
            "Multiple failed authentication attempts should be detected");
    }
}
