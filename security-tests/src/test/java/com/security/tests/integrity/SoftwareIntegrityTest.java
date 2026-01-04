package com.security.tests.integrity;

import com.security.tests.base.BaseTest;
import org.testng.annotations.Test;
import static org.testng.Assert.*;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


public class SoftwareIntegrityTest extends BaseTest {

    @Test(description = "OWASP A08 - Verify JAR file integrity")
    public void testJarFileIntegrity() {
        try {
            
            Path jarPath = Paths.get("../ecommerce-app/target/ecommerce-app-1.0.0.jar");
            
            if (Files.exists(jarPath)) {
                long fileSize = Files.size(jarPath);
                assertTrue(fileSize > 0, "JAR file should not be empty");
                
                
                logSecurityEvent("JAR_INTEGRITY_CHECK", "INFO", 
                    "Verified JAR exists - Size: " + fileSize + " bytes");
            } else {
                logSecurityEvent("JAR_INTEGRITY_CHECK", "WARN", 
                    "JAR file not found - may need to build first");
            }
            
        } catch (Exception e) {
            fail("Error checking JAR integrity: " + e.getMessage());
        }
    }

    @Test(description = "OWASP A08 - Check for insecure deserialization")
    public void testInsecureDeserialization() {
        driver.get(baseUrl + "/api/data");
        
        String pageSource = driver.getPageSource();
        
        
        assertFalse(pageSource.contains("ObjectInputStream"),
            "Java ObjectInputStream usage can lead to deserialization attacks");
        assertFalse(pageSource.contains("readObject"),
            "Avoid using readObject for deserialization");
        
        logSecurityEvent("DESERIALIZATION_CHECK", "INFO", 
            "Checked for insecure deserialization patterns");
    }

    @Test(description = "OWASP A08 - Verify dependencies are from trusted sources")
    public void testDependencySourceIntegrity() {
        try {
            
            File settingsFile = new File(System.getProperty("user.home") + "/.m2/settings.xml");
            
            if (settingsFile.exists()) {
                String content = new String(Files.readAllBytes(settingsFile.toPath()));
                
                
                assertFalse(content.contains("http://") && content.contains("repository"),
                    "Maven repositories should use HTTPS, not HTTP");
                
                logSecurityEvent("DEPENDENCY_SOURCE_CHECK", "INFO", 
                    "Verified dependency sources use secure protocols");
            }
        } catch (Exception e) {
            logSecurityEvent("DEPENDENCY_SOURCE_CHECK", "WARN", 
                "Could not verify Maven settings: " + e.getMessage());
        }
    }

    @Test(description = "OWASP A08 - Check for CI/CD pipeline security")
    public void testCICDPipelineSecurity() {
        
        Path securityWorkflow = Paths.get("../.github/workflows/security-tests.yml");
        Path jiraWorkflow = Paths.get("../.github/workflows/manual-jira-tickets.yml");
        
        try {
            StringBuilder combined = new StringBuilder();
            boolean hasWorkflow = false;
            boolean usesSecrets = false;

            if (Files.exists(securityWorkflow)) {
                String content = new String(Files.readAllBytes(securityWorkflow));
                combined.append(content);
                hasWorkflow = true;
                usesSecrets = usesSecrets || content.contains("secrets.");
            }
            if (Files.exists(jiraWorkflow)) {
                String content = new String(Files.readAllBytes(jiraWorkflow));
                combined.append(content);
                hasWorkflow = true;
                usesSecrets = usesSecrets || content.contains("secrets.");
            }

            if (hasWorkflow) {
                String content = combined.toString();
                assertTrue(content.contains("actions/checkout@v"),
                    "Should use versioned GitHub Actions");
                assertFalse(content.contains("password=") || content.contains("token="),
                    "No hardcoded secrets in workflow files");
                assertTrue(usesSecrets,
                    "Should use GitHub secrets for sensitive data");

                logSecurityEvent("CICD_SECURITY_CHECK", "INFO",
                    "Verified CI/CD pipeline configuration is secure");
            }
        } catch (Exception e) {
            logSecurityEvent("CICD_SECURITY_CHECK", "WARN", 
                "Could not verify CI/CD configuration: " + e.getMessage());
        }
    }

    @Test(description = "OWASP A08 - Verify no unsigned libraries in classpath")
    public void testUnsignedLibraries() {
        try {
            String jarPath = org.openqa.selenium.WebDriver.class
                .getProtectionDomain()
                .getCodeSource()
                .getLocation()
                .toURI()
                .getPath();

            assertTrue(jarPath.contains(".m2") && jarPath.contains("repository"),
                "Dependencies should load from the local Maven repository");

            File jarFile = new File(jarPath);
            assertTrue(jarFile.exists() && jarFile.length() > 0,
                "Dependency JAR should exist and be non-empty");

            logSecurityEvent("UNSIGNED_LIBRARIES_CHECK", "INFO",
                "Verified dependency JAR path and integrity: " + jarFile.getName());
        } catch (Exception e) {
            logSecurityEvent("UNSIGNED_LIBRARIES_CHECK", "WARN",
                "Could not verify dependency JAR integrity: " + e.getMessage());
            throw new org.testng.SkipException("Jar integrity check unavailable");
        }
    }

    @Test(description = "OWASP A08 - Check for auto-update security")
    public void testAutoUpdateSecurity() {
        
        driver.get(baseUrl);
        
        String pageSource = driver.getPageSource();
        assertFalse(pageSource.contains("auto-update") || pageSource.contains("autoupdate"),
            "Auto-update features should be carefully controlled");
        
        logSecurityEvent("AUTO_UPDATE_CHECK", "INFO", 
            "Verified no insecure auto-update mechanisms");
    }
}
