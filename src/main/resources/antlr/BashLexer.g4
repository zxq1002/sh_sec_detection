lexer grammar BashLexer;

WHITESPACE: [ \t]+ -> skip;
NEWLINE: '\r'? '\n';

PIPE: '|';
ANDAND: '&&';
OROR: '||';
SEMICOLON: ';';
AMPERSAND: '&';

LPAREN: '(';
RPAREN: ')';
LBRACE: '{';
RBRACE: '}';

REDIRECT_OUT: '>' -> mode(REDIRECT_MODE);
REDIRECT_APPEND: '>>' -> mode(REDIRECT_MODE);
REDIRECT_IN: '<' -> mode(REDIRECT_MODE);

WORD: ( ~[ \t\n\r(){}|&;<>] | ESCAPED_CHAR )+;
fragment ESCAPED_CHAR: '\\' .;

mode REDIRECT_MODE;
REDIRECT_WHITESPACE: [ \t]+ -> skip;
FILENAME: ( ~[ \t\n\r] | ESCAPED_CHAR )+ -> mode(DEFAULT_MODE);
