package com.security.tests.api;

import com.security.tests.base.BaseTest;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig; 
import io.restassured.response.Response;
import org.testng.Assert;
import org.testng.annotations.Test;

public class APIAuthenticationTest extends BaseTest {
    
    @Test(description = "Test API authentication required")
    public void testAPIAuth() {
        RestAssured.baseURI = baseUrl;
        
        
        Response response = RestAssured
            .given()
            .config(RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false)))
            .get("/api/security/events");
        
        
        
        Assert.assertTrue(response.statusCode() == 401 || response.statusCode() == 302,
            "API should require authentication (Received: " + response.statusCode() + ")");
        assertSecurityEventLogged("API_AUTH_FAILURE");
    }


    @Override
    protected boolean useWebDriver() {
        return false;
    }

}
