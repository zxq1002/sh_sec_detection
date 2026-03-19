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

    @Test
    void testPipeCommandWithBlacklistShouldBeBlocked() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("builtin-ps")
                        .pattern("^\\s*ps\\b")
                        .whitelist()
                        .riskLevel(RiskLevel.SAFE)
                        .build())
                .withRule(Rule.builder()
                        .id("builtin-rm-rf")
                        .pattern("rm\\s+.*-rf")
                        .blacklist()
                        .riskLevel(RiskLevel.RISK)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("ps -ef | rm -rf xxx.sh");
        assertFalse(result.isPassed());
    }

    @Test
    void testEchoWithWriteRedirectionShouldBeBlocked() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("builtin-echo")
                        .pattern("^\\s*echo\\b")
                        .whitelist()
                        .riskLevel(RiskLevel.SAFE)
                        .build())
                .withRule(Rule.builder()
                        .id("builtin-file-write")
                        .pattern("\\s*>\\s*[^\\s]|\\s*1>\\s*[^\\s]|\\s*2>\\s*[^\\s]|\\s*>>\\s*[^\\s]")
                        .blacklist()
                        .riskLevel(RiskLevel.RISK)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("echo '123' > 123.sh");
        assertFalse(result.isPassed());
    }

    @Test
    void testEchoWithAppendRedirectionShouldBeBlocked() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("builtin-echo")
                        .pattern("^\\s*echo\\b")
                        .whitelist()
                        .riskLevel(RiskLevel.SAFE)
                        .build())
                .withRule(Rule.builder()
                        .id("builtin-file-write")
                        .pattern("\\s*>\\s*[^\\s]|\\s*1>\\s*[^\\s]|\\s*2>\\s*[^\\s]|\\s*>>\\s*[^\\s]")
                        .blacklist()
                        .riskLevel(RiskLevel.RISK)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("echo '123' >> 123.sh");
        assertFalse(result.isPassed());
    }

    @Test
    void testSimpleWhitelistCommandShouldPass() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("builtin-ps")
                        .pattern("^\\s*ps\\b")
                        .whitelist()
                        .riskLevel(RiskLevel.SAFE)
                        .build())
                .withRule(Rule.builder()
                        .id("builtin-rm-rf")
                        .pattern("rm\\s+.*-rf")
                        .blacklist()
                        .riskLevel(RiskLevel.RISK)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("ps -ef");
        assertTrue(result.isPassed());
    }

    @Test
    void testMultipleCommandsWithBlacklistShouldBeBlocked() {
        ShellDetector detector = ShellDetector.builder()
                .withRule(Rule.builder()
                        .id("builtin-ls")
                        .pattern("^\\s*ls\\b")
                        .whitelist()
                        .riskLevel(RiskLevel.SAFE)
                        .build())
                .withRule(Rule.builder()
                        .id("builtin-rm-rf")
                        .pattern("rm\\s+.*-rf")
                        .blacklist()
                        .riskLevel(RiskLevel.RISK)
                        .build())
                .withThreshold(RiskLevel.RISK)
                .build();

        DetectionResult result = detector.detect("ls -la; rm -rf /tmp");
        assertFalse(result.isPassed());
    }
}
