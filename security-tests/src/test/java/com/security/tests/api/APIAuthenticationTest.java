package com.security.tests.api;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig; // Import this
import io.restassured.response.Response;
import org.testng.Assert;
import org.testng.annotations.Test;

public class APIAuthenticationTest extends BaseTest {
    
    @Test(description = "Test API authentication required")
    public void testAPIAuth() {
        RestAssured.baseURI = baseUrl;
        
        // FIX: Disable redirect following to catch the 302 status
        Response response = RestAssured
            .given()
            .config(RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false)))
            .get("/api/transactions");
        
        // API should require authentication (401) or redirect to login (302)
        // A 200 OK here means we accidentally followed the redirect to the login page
        Assert.assertTrue(response.statusCode() == 401 || response.statusCode() == 302,
            "API should require authentication (Received: " + response.statusCode() + ")");
        
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "API_AUTH_TEST",
            "anonymous",
            "authentication_test",
            "Tested API authentication requirement"
        );
        eventLogger.logSecurityEvent(event);
    }
}