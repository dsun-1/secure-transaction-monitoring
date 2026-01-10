package com.security.tests.injection;

import com.security.tests.base.BaseTest;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.testng.Assert;
import org.testng.annotations.Test;

public class XSSTest extends BaseTest {
    
    @Test(description = "Test XSS in login form")
    public void testXSSInLogin() {
        navigateToUrl("/login");
        
        String xssPayload = "<script>alert('XSS')</script>";
        
        WebElement username = driver.findElement(By.id("username"));
        WebElement password = driver.findElement(By.id("password"));
        
        username.sendKeys(xssPayload);
        password.sendKeys("password");
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@type='submit']"));
        loginButton.click();
        
        
        String pageSource = driver.getPageSource();
        Assert.assertFalse(pageSource.contains("<script>alert('XSS')</script>"),
            "XSS payload should be escaped");
        
        assertSecurityEventLogged("XSS_ATTEMPT");
    }
    
    @Test(description = "Test reflected XSS")
    public void testReflectedXSS() {
        
        String xssPayload = "<img src=x onerror=alert('XSS')>";
        navigateToUrl("/products?search=" + xssPayload);
        
        String pageSource = driver.getPageSource();
        Assert.assertFalse(pageSource.contains("onerror=alert"),
            "Reflected XSS should be escaped");
        
        assertSecurityEventLogged("XSS_ATTEMPT");
    }

}
