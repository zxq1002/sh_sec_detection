parser grammar BashParser;
options { tokenVocab=BashLexer; }

parse: commandList EOF;

commandList: command (SEMICOLON command)* SEMICOLON?;

command: pipeline ( (ANDAND | OROR) pipeline )*;

pipeline: simpleCommand (PIPE simpleCommand)*;

simpleCommand: WORD+;
