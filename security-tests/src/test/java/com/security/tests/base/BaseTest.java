package com.security.tests.base;

import java.time.Duration;
import java.time.LocalDateTime;
import java.net.HttpURLConnection;
import java.net.URL;
import io.github.bonigarcia.wdm.WebDriverManager;
import io.restassured.RestAssured;
import io.restassured.config.HttpClientConfig;
import io.restassured.config.RestAssuredConfig;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeSuite;
import com.security.tests.utils.SecurityEventLogger;



public class BaseTest {
    
    protected WebDriver driver;
    
    protected String baseUrl = "http://localhost:8080"; 
    protected SecurityEventLogger eventLogger;
    protected LocalDateTime testStart;
    private static final int APP_READY_ATTEMPTS = 30;
    private static final int APP_READY_DELAY_SECONDS = 2;
    private static final int APP_READY_TIMEOUT_MS = 2000;
    
    @BeforeSuite
    public void suiteSetup() {
        
        SecurityEventLogger.initializeDatabase();
        configureRestAssuredTimeouts();
        waitForAppReady(resolveBaseUrl());
    }
    
    @BeforeMethod
    public void setUp() {
        
        String propUrl = System.getProperty("baseUrl");
        if (propUrl != null && !propUrl.isEmpty()) {
            this.baseUrl = propUrl;
        }

        eventLogger = new SecurityEventLogger();
        testStart = LocalDateTime.now().minusSeconds(1);

        if (!useWebDriver()) {
            return;
        }

        String browser = System.getProperty("browser", "chrome").toLowerCase();
        boolean headless = Boolean.parseBoolean(System.getProperty("headless", "true"));
        
        switch (browser) {
            case "firefox":
                WebDriverManager.firefoxdriver().setup();
                FirefoxOptions firefoxOptions = new FirefoxOptions();
                if (headless) {
                    firefoxOptions.addArguments("--headless");
                }
                driver = new FirefoxDriver(firefoxOptions);
                break;
                
            case "chrome":
            default:
                WebDriverManager.chromedriver().setup();
                ChromeOptions chromeOptions = new ChromeOptions();
                if (headless) {
                    chromeOptions.addArguments("--headless=new");
                    chromeOptions.addArguments("--window-size=1366,768");
                }
                chromeOptions.addArguments("--no-sandbox");
                chromeOptions.addArguments("--disable-dev-shm-usage");
                chromeOptions.addArguments("--disable-gpu");
                
                chromeOptions.addArguments("--remote-allow-origins=*");
                driver = new ChromeDriver(chromeOptions);
                break;
        }
        
        if (!headless) {
            driver.manage().window().maximize();
        }
        
        
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(20));
        
        
        driver.manage().timeouts().pageLoadTimeout(Duration.ofSeconds(60));
    }
    
    @AfterMethod
    public void tearDown() {
        if (driver != null) {
            driver.quit();
        }
    }
    
    protected void navigateToUrl(String path) {
        driver.get(baseUrl + path);
    }

    protected void assertSecurityEventLogged(String eventType) {
        boolean found = eventLogger.waitForEvent(eventType, testStart, Duration.ofSeconds(5));
        Assert.assertTrue(found, "Expected security event not found: " + eventType);
    }

    protected void logSecurityEvent(String eventType, String severity, String description) {
        if (eventLogger != null) {
            com.security.tests.utils.SecurityEvent event = new com.security.tests.utils.SecurityEvent();
            event.setEventType(eventType);
            event.setSeverity(severity);
            event.setEventDetails(description);
            event.setUsername("test-user");
            event.setIpAddress("127.0.0.1");
            eventLogger.logSecurityEvent(event);
        }
    }

    protected boolean useWebDriver() {
        return true;
    }

    private static void configureRestAssuredTimeouts() {
        RestAssured.config = RestAssuredConfig.config()
            .httpClient(HttpClientConfig.httpClientConfig()
                .setParam("http.connection.timeout", 5000)
                .setParam("http.socket.timeout", 5000));
    }

    private static String resolveBaseUrl() {
        String property = System.getProperty("baseUrl");
        if (property != null && !property.isBlank()) {
            return property;
        }
        return "http://localhost:8080";
    }

    private static void waitForAppReady(String baseUrl) {
        for (int attempt = 1; attempt <= APP_READY_ATTEMPTS; attempt++) {
            if (isAppReady(baseUrl)) {
                return;
            }
            try {
                Thread.sleep(APP_READY_DELAY_SECONDS * 1000L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        throw new IllegalStateException("App is not reachable at " + baseUrl + ". Start the app and retry.");
    }

    private static boolean isAppReady(String baseUrl) {
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(baseUrl).openConnection();
            connection.setConnectTimeout(APP_READY_TIMEOUT_MS);
            connection.setReadTimeout(APP_READY_TIMEOUT_MS);
            connection.setRequestMethod("GET");
            int status = connection.getResponseCode();
            return status >= 200 && status < 500;
        } catch (Exception e) {
            return false;
        }
    }

}
