package com.security.tests.auth;

import com.security.tests.base.BaseTest;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.JavascriptExecutor; 
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;         
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import io.github.bonigarcia.wdm.WebDriverManager;
import java.time.Duration;
import org.testng.Assert;
import org.testng.annotations.Test;



public class SessionHijackingTest extends BaseTest {
    
    @Test(priority = 1, description = "Test session hijacking by stealing session cookie")
    public void testSessionCookieStealing() {
        
        navigateToUrl("/login");
        driver.findElement(By.id("username")).sendKeys("testuser");
        driver.findElement(By.id("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        
        new WebDriverWait(driver, Duration.ofSeconds(10))
            .until(ExpectedConditions.not(ExpectedConditions.urlContains("/login")));
        
        
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        Assert.assertNotNull(sessionCookie, "Session cookie should be present after login");
        
        
        boolean isHttpOnly = sessionCookie.isHttpOnly();
        Assert.assertTrue(isHttpOnly, 
            "Session cookie should have HttpOnly flag to prevent XSS-based hijacking");
        
        
        boolean isSecure = sessionCookie.isSecure();
        
        // Note: In production, session cookies should be secure
        if (!isSecure && !driver.getCurrentUrl().startsWith("http://localhost")) {
            System.out.println("Warning: Session cookie is not secure in non-localhost environment");
        }
    }
    
    @Test(priority = 2, description = "Test session reuse after logout")
    public void testSessionReuseAfterLogout() {
        
        navigateToUrl("/login");
        driver.findElement(By.id("username")).sendKeys("testuser");
        driver.findElement(By.id("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        
        new WebDriverWait(driver, Duration.ofSeconds(10))
            .until(ExpectedConditions.not(ExpectedConditions.urlContains("/login")));


        
        Cookie oldSessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        String oldSessionId = oldSessionCookie != null ? oldSessionCookie.getValue() : "";
        
        // Log the old session ID for debugging
        System.out.println("Old session ID: " + oldSessionId);
        
        navigateToUrl("/products"); 
        
        
        WebElement logoutBtn = driver.findElement(By.id("logoutButton"));
        ((JavascriptExecutor) driver).executeScript("arguments[0].click();", logoutBtn);
        
        
        new WebDriverWait(driver, Duration.ofSeconds(10))
            .until(ExpectedConditions.urlContains("/login"));


        
        if (oldSessionCookie != null) {
            driver.manage().addCookie(oldSessionCookie);
        }
        
        
        navigateToUrl("/account");
        
        
        boolean isRedirectedToLogin = driver.getCurrentUrl().contains("/login") ||
                                     driver.getPageSource().contains("Please log in");
        
        Assert.assertTrue(isRedirectedToLogin, 
            "Old session should not be valid after logout - session hijacking vulnerability!");
        
        assertSecurityEventLogged("SESSION_HIJACK_ATTEMPT");
    }
    
    @Test(priority = 3, description = "Test concurrent session detection")
    public void testConcurrentSessionDetection() {
        navigateToUrl("/login");
        driver.findElement(By.id("username")).sendKeys("testuser");
        driver.findElement(By.id("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();


        new WebDriverWait(driver, Duration.ofSeconds(10))
            .until(ExpectedConditions.not(ExpectedConditions.urlContains("/login")));

        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        Assert.assertNotNull(sessionCookie, "Session cookie should be present after login");

        WebDriver secondDriver = createSecondaryDriver("Codex-Session-Probe/1.0");
        try {
            secondDriver.get(baseUrl + "/");
            secondDriver.manage().addCookie(sessionCookie);
            secondDriver.get(baseUrl + "/account");
        } finally {
            secondDriver.quit();
        }

        assertSecurityEventLogged("SESSION_HIJACK_ATTEMPT");
    }



    private WebDriver createSecondaryDriver(String userAgent) {
        String browser = System.getProperty("browser", "chrome").toLowerCase();
        boolean headless = Boolean.parseBoolean(System.getProperty("headless", "true"));



        switch (browser) {
            case "firefox":
                WebDriverManager.firefoxdriver().setup();
                FirefoxOptions firefoxOptions = new FirefoxOptions();
                if (headless) {
                    firefoxOptions.addArguments("--headless");
                }
                if (userAgent != null && !userAgent.isBlank()) {
                    firefoxOptions.addPreference("general.useragent.override", userAgent);
                }
                return new FirefoxDriver(firefoxOptions);
            case "chrome":
            default:
                WebDriverManager.chromedriver().setup();
                ChromeOptions chromeOptions = new ChromeOptions();
                if (headless) {
                    chromeOptions.addArguments("--headless=new");
                }
                if (userAgent != null && !userAgent.isBlank()) {
                    chromeOptions.addArguments("--user-agent=" + userAgent);
                }
                chromeOptions.addArguments("--no-sandbox");
                chromeOptions.addArguments("--disable-dev-shm-usage");
                chromeOptions.addArguments("--disable-gpu");
                chromeOptions.addArguments("--remote-allow-origins=*");
                return new ChromeDriver(chromeOptions);
        }
    }

}
