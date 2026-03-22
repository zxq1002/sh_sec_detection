package com.example.shelldetector.parser;

/**
 * ShellParser 工厂类
 * <p>
 * 根据配置的 ParserType 创建对应的解析器实例。
 * </p>
 */
public class ShellParserFactory {

    private ShellParserFactory() {
        // 工具类，不允许实例化
    }

    /**
     * 创建指定类型的解析器
     *
     * @param type 解析器类型
     * @return ShellParser 实例
     * @throws IllegalArgumentException 如果类型未知
     */
    public static ShellParser createParser(ParserType type) {
        switch (type) {
            case SIMPLE:
                return new SimpleShellParser();
            case ANTLR:
                return new AntlrShellParser();
            default:
                throw new IllegalArgumentException("Unknown parser type: " + type);
        }
    }

    /**
     * 创建默认解析器（SIMPLE）
     *
     * @return 默认的 SimpleShellParser 实例
     */
    public static ShellParser createDefaultParser() {
        return createParser(ParserType.SIMPLE);
    }
}
