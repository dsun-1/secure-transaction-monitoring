package com.security.tests.api;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.testng.Assert;
import org.testng.annotations.Test;

public class DataExposureTest extends BaseTest {
    
    @Test(description = "Test for sensitive data exposure")
    public void testDataExposure() {
        RestAssured.baseURI = baseUrl;
        
        // Test that sensitive data is not exposed on public pages
        Response response = RestAssured
            .given()
            .get("/products");
        
        String body = response.getBody().asString();
        
        // Check that passwords are not exposed
        Assert.assertFalse(body.toLowerCase().contains("password"),
            "Password fields should not be exposed in API responses");
        
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "DATA_EXPOSURE_TEST",
            "test_user",
            "information_disclosure_test",
            "Tested for sensitive data exposure"
        );
        eventLogger.logSecurityEvent(event);
    }
}
