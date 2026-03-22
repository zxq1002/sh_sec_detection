parser grammar BashParser;
options { tokenVocab=BashLexer; }

@header {
package com.example.shelldetector.parser.antlr;
}

parse: commandList EOF;

commandList: command (SEMICOLON command)* SEMICOLON?;

command: pipeline ( (ANDAND | OROR) pipeline )*;

pipeline: simpleCommand (PIPE simpleCommand)*;

simpleCommand: word+;

// 支持命令替换和其他 shell 结构
word: WORD
    | DOLLAR LPAREN commandList RPAREN
    | BACKTICK commandList BACKTICK
    ;
