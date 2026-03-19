package com.example.shelldetector.model;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RiskLevelTest {

    @Test
    void testRiskLevelOrder() {
        assertTrue(RiskLevel.DANGER.isHigherOrEqualTo(RiskLevel.RISK));
        assertTrue(RiskLevel.RISK.isHigherOrEqualTo(RiskLevel.SAFE));
        assertTrue(RiskLevel.DANGER.isHigherOrEqualTo(RiskLevel.DANGER));
        assertFalse(RiskLevel.SAFE.isHigherOrEqualTo(RiskLevel.RISK));
    }
}
