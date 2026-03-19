package com.example.shelldetector.parser;

import com.example.shelldetector.exception.ShellParseException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

public class ShellCommandExtractor {

    private static final Pattern COMMAND_DELIMITERS = Pattern.compile("[;|&]");

    public List<String> extractCommands(String shellCommand) {
        if (shellCommand == null || shellCommand.trim().isEmpty()) {
            return Collections.emptyList();
        }

        try {
            List<String> commands = new ArrayList<>();
            String[] parts = COMMAND_DELIMITERS.split(shellCommand);
            for (String part : parts) {
                String trimmed = removeRedirections(part.trim());
                if (!trimmed.isEmpty()) {
                    commands.add(trimmed);
                }
            }
            return commands;
        } catch (Exception e) {
            throw new ShellParseException("Failed to parse shell command: " + shellCommand, e);
        }
    }

    private String removeRedirections(String command) {
        return command.replaceAll("\\s*[<>]\\s*[^\\s]+", "")
                      .replaceAll("\\s*[12]>&?\\s*[^\\s]+", "");
    }
}
