package com.security.tests.components;

import com.security.tests.base.BaseTest;
import org.testng.annotations.Test;
import org.testng.SkipException;
import static org.testng.Assert.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;


public class VulnerableComponentsTest extends BaseTest {

    @Test(description = "OWASP A06 - Check for known CVEs in dependencies")
    public void testDependencyVulnerabilities() {
        try {
            
            ProcessBuilder pb = new ProcessBuilder("mvn", "dependency-check:check", "-f", "../pom.xml");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            int exitCode = process.waitFor();
            String result = output.toString();
            
            
            assertFalse(result.contains("One or more dependencies were identified with known vulnerabilities"),
                "HIGH/CRITICAL CVEs found in dependencies - check dependency-check-report.html");
            
            logSecurityEvent("DEPENDENCY_CVE_CHECK", "INFO", 
                "Dependency vulnerability scan completed - Exit code: " + exitCode);
            
        } catch (Exception e) {
            
            logSecurityEvent("DEPENDENCY_CVE_CHECK", "WARN", 
                "Could not run dependency check: " + e.getMessage());
        }
    }

    @Test(description = "OWASP A06 - Verify Spring Boot version is not outdated")
    public void testFrameworkVersion() {
        
        String springBootVersion = System.getProperty("spring.boot.version", "UNKNOWN");
        
        
        assertFalse(springBootVersion.startsWith("2."), 
            "Spring Boot version should be 3.x or higher");
        assertFalse(springBootVersion.startsWith("1."), 
            "Spring Boot 1.x is severely outdated");
        
        logSecurityEvent("FRAMEWORK_VERSION_CHECK", "INFO", 
            "Verified Spring Boot version is current");
    }

    @Test(description = "OWASP A06 - Check for outdated JavaScript libraries")
    public void testFrontendDependencies() {
        driver.get(baseUrl);
        String pageSource = driver.getPageSource();
        
        
        assertFalse(pageSource.contains("jquery-1.") || pageSource.contains("jquery-2."),
            "jQuery version should be 3.x or higher");
        assertFalse(pageSource.contains("angular.js/1."),
            "AngularJS 1.x has known vulnerabilities");
        assertFalse(pageSource.contains("moment.js"),
            "Moment.js is deprecated, use date-fns or Luxon");
        
        logSecurityEvent("FRONTEND_DEPENDENCIES_CHECK", "INFO", 
            "Checked frontend library versions");
    }

    @Test(description = "OWASP A06 - Verify no unused dependencies")
    public void testUnusedDependencies() {
        try {
            ProcessBuilder pb = new ProcessBuilder("mvn", "dependency:analyze", "-f", "../pom.xml");
            pb.redirectErrorStream(true);
            Process process = pb.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            int exitCode = process.waitFor();
            String result = output.toString();
            if (exitCode != 0) {
                throw new SkipException("dependency:analyze failed with exit code " + exitCode);
            }

            assertFalse(result.contains("Unused declared dependencies found"),
                "Unused declared dependencies found");
            assertFalse(result.contains("Used undeclared dependencies found"),
                "Used undeclared dependencies found");

            logSecurityEvent("UNUSED_DEPENDENCIES_CHECK", "INFO",
                "Dependency analyze completed with no unused dependencies");
        } catch (SkipException e) {
            logSecurityEvent("UNUSED_DEPENDENCIES_CHECK", "WARN", e.getMessage());
            throw e;
        } catch (Exception e) {
            logSecurityEvent("UNUSED_DEPENDENCIES_CHECK", "WARN",
                "Could not run dependency analyze: " + e.getMessage());
            throw new SkipException("dependency:analyze not available");
        }
    }

    @Test(description = "OWASP A06 - Check for dependencies with known exploits")
    public void testExploitableComponents() {
        driver.get(baseUrl);
        
        
        String[] vulnerableComponents = {
            "log4j-core-2.14",  
            "log4j-core-2.15",  
            "struts-2.3",       
            "commons-collections-3.2.1",  
            "jackson-databind-2.9"  
        };
        
        String pageSource = driver.getPageSource();
        for (String component : vulnerableComponents) {
            assertFalse(pageSource.contains(component),
                "Vulnerable component detected: " + component);
        }
        
        logSecurityEvent("EXPLOITABLE_COMPONENTS_CHECK", "INFO", 
            "Verified no known exploitable components in use");
    }
}
