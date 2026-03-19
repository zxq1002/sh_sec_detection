package com.example.shelldetector.persistence;

import com.example.shelldetector.exception.RulePersistenceException;
import com.example.shelldetector.model.Rule;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RuleSaver {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static void saveToJson(List<Rule> rules, File file) {
        if (rules == null) {
            throw new IllegalArgumentException("Rules cannot be null");
        }
        if (file == null) {
            throw new IllegalArgumentException("File cannot be null");
        }
        try {
            Map<String, Object> data = new HashMap<>();
            data.put("version", "1.0");
            data.put("rules", rules);
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(file, data);
        } catch (IOException e) {
            throw new RulePersistenceException("Failed to save rules to " + file, e);
        }
    }

    public static void saveToJson(List<Rule> rules, String path) {
        if (path == null || path.trim().isEmpty()) {
            throw new IllegalArgumentException("Path cannot be null or empty");
        }
        saveToJson(rules, new File(path));
    }
}
