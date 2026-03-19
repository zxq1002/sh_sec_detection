package com.example.shelldetector.config;

import com.example.shelldetector.model.RiskLevel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * DetectionConfig 测试类
 * <p>
 * 测试检测配置的功能，包括：
 * - 默认配置
 * - 自定义配置
 * - Builder 模式
 * - 参数验证
 * </p>
 */
class DetectionConfigTest {

    @Test
    void testDefaultConfig() {
        DetectionConfig config = new DetectionConfig();
        assertEquals(RiskLevel.RISK, config.getThreshold());
        assertTrue(config.isFailOnParseError());
    }

    @Test
    void testBuilderDefaultConfig() {
        DetectionConfig config = DetectionConfig.builder().build();
        assertEquals(RiskLevel.RISK, config.getThreshold());
        assertTrue(config.isFailOnParseError());
    }

    @Test
    void testSetThreshold() {
        DetectionConfig config = new DetectionConfig();
        config.setThreshold(RiskLevel.DANGER);
        assertEquals(RiskLevel.DANGER, config.getThreshold());
    }

    @Test
    void testSetThresholdWithNull() {
        DetectionConfig config = new DetectionConfig();
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            config.setThreshold(null);
        });
        assertEquals("Threshold cannot be null", exception.getMessage());
    }

    @Test
    void testSetFailOnParseError() {
        DetectionConfig config = new DetectionConfig();
        config.setFailOnParseError(false);
        assertFalse(config.isFailOnParseError());

        config.setFailOnParseError(true);
        assertTrue(config.isFailOnParseError());
    }

    @Test
    void testBuilderWithThreshold() {
        DetectionConfig config = DetectionConfig.builder()
                .threshold(RiskLevel.DANGER)
                .build();
        assertEquals(RiskLevel.DANGER, config.getThreshold());
    }

    @Test
    void testBuilderWithThresholdNull() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            DetectionConfig.builder().threshold(null).build();
        });
        assertEquals("Threshold cannot be null", exception.getMessage());
    }

    @Test
    void testBuilderWithFailOnParseError() {
        DetectionConfig config = DetectionConfig.builder()
                .failOnParseError(false)
                .build();
        assertFalse(config.isFailOnParseError());
    }

    @Test
    void testBuilderWithAllOptions() {
        DetectionConfig config = DetectionConfig.builder()
                .threshold(RiskLevel.SAFE)
                .failOnParseError(false)
                .build();
        assertEquals(RiskLevel.SAFE, config.getThreshold());
        assertFalse(config.isFailOnParseError());
    }

    @Test
    void testSetThresholdAfterCreation() {
        DetectionConfig config = DetectionConfig.builder()
                .threshold(RiskLevel.RISK)
                .build();
        assertEquals(RiskLevel.RISK, config.getThreshold());

        config.setThreshold(RiskLevel.DANGER);
        assertEquals(RiskLevel.DANGER, config.getThreshold());
    }

    @Test
    void testSetFailOnParseErrorAfterCreation() {
        DetectionConfig config = DetectionConfig.builder()
                .failOnParseError(true)
                .build();
        assertTrue(config.isFailOnParseError());

        config.setFailOnParseError(false);
        assertFalse(config.isFailOnParseError());
    }

    @Test
    void testBuilderMultipleThresholdCalls() {
        DetectionConfig config = DetectionConfig.builder()
                .threshold(RiskLevel.SAFE)
                .threshold(RiskLevel.RISK)
                .threshold(RiskLevel.DANGER)
                .build();
        assertEquals(RiskLevel.DANGER, config.getThreshold());
    }

    @Test
    void testBuilderMultipleFailOnParseErrorCalls() {
        DetectionConfig config = DetectionConfig.builder()
                .failOnParseError(true)
                .failOnParseError(false)
                .failOnParseError(true)
                .build();
        assertTrue(config.isFailOnParseError());
    }

    @Test
    void testThresholdAllLevels() {
        DetectionConfig config = new DetectionConfig();

        config.setThreshold(RiskLevel.SAFE);
        assertEquals(RiskLevel.SAFE, config.getThreshold());

        config.setThreshold(RiskLevel.RISK);
        assertEquals(RiskLevel.RISK, config.getThreshold());

        config.setThreshold(RiskLevel.DANGER);
        assertEquals(RiskLevel.DANGER, config.getThreshold());
    }
}
