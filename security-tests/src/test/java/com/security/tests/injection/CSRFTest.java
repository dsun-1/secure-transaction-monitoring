package com.security.tests.injection;

import com.security.tests.base.BaseTest;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.testng.Assert;
import org.testng.annotations.Test;

public class CSRFTest extends BaseTest {
    
    @Test(description = "Test CSRF token presence")
    public void testCSRFTokenPresent() {
        navigateToUrl("/login");
        
        String pageSource = driver.getPageSource();
        Assert.assertTrue(pageSource.contains("_csrf") || pageSource.contains("csrf"),
            "CSRF token should be present in forms");
    }

    @Test(description = "Test CSRF protection rejects missing tokens")
    public void testCSRFTokenMissing() {
        RestAssured.baseURI = baseUrl;
        Response response = RestAssured
            .given()
            .redirects().follow(false)
            .post("/cart/clear");
        Assert.assertEquals(response.statusCode(), 403,
            "Missing CSRF token should be rejected");
        assertSecurityEventLogged("CSRF_VIOLATION");
    }
}
