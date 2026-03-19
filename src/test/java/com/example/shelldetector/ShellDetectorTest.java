package com.example.shelldetector;

import com.example.shelldetector.model.DetectionResult;
import com.example.shelldetector.model.RiskLevel;
import com.example.shelldetector.model.Rule;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ShellDetectorTest {

    @Test
    void testSimpleDetection() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("test-rm")
                        .pattern("rm\\s+-rf")
                        .blacklist()
                        .riskLevel(RiskLevel.DANGER)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("rm -rf /tmp");
        assertFalse(result.isPassed());
    }

    @Test
    void testWhitelistEntireCommand() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("safe-cmd")
                        .pattern("ls -la /tmp")
                        .whitelist()
                        .build())
                .withRule(Rule.builder()
                        .id("danger-rm")
                        .pattern("rm.*")
                        .blacklist()
                        .riskLevel(RiskLevel.DANGER)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("ls -la /tmp");
        assertTrue(result.isPassed());
    }
}
