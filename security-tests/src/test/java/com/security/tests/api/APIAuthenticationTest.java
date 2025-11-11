package com.security.tests.api;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.testng.Assert;
import org.testng.annotations.Test;

public class APIAuthenticationTest extends BaseTest {
    
    @Test(description = "Test API authentication required")
    public void testAPIAuth() {
        RestAssured.baseURI = baseUrl;
        
        // Test accessing API without authentication
        Response response = RestAssured
            .given()
            .get("/api/transactions");
        
        // API should require authentication (401) or redirect to login
        Assert.assertTrue(response.statusCode() == 401 || response.statusCode() == 302,
            "API should require authentication");
        
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "API_AUTH_TEST",
            "anonymous",
            "authentication_test",
            "Tested API authentication requirement"
        );
        eventLogger.logSecurityEvent(event);
    }
}
