import math
import operator

import ply.lex as lex
import ply.yacc as yacc

# --- Lexer ---

reserved = {
    'sqrt': 'SQRT',
    'pow': 'POW',
    'concat': 'CONCAT',
    'if': 'IF',
    'else': 'ELSE',
    'print': 'PRINT',
    'for': 'FOR',
    'while': 'WHILE',
    'do': 'DO',
}

tokens = (
    'NUMBER',
    'STRING',
    'IDENTIFIER',
    'PLUS',
    'MINUS',
    'TIMES',
    'DIVIDE',
    'MODULO',
    'LPAREN',
    'RPAREN',
    'LBRACE',
    'RBRACE',
    'COMMA',
    'EQUALS',
    'PLUSEQ',
    'MINUSEQ',
    'TIMESEQ',
    'DIVEQ',
    'MODEQ',
    'PLUSPLUS',
    'MINUSMINUS',
    'SEMI',
    'GT',
    'LT',
    'GE',
    'LE',
    'EQ',
    'NE',
) + tuple(reserved.values())

t_PLUS = r'\+'
t_MINUS = r'-'
t_TIMES = r'\*'
t_DIVIDE = r'/'
t_MODULO = r'%'
t_LPAREN = r'\('
t_RPAREN = r'\)'
t_LBRACE = r'\{'
t_RBRACE = r'\}'
t_COMMA = r','
t_EQUALS = r'='
t_PLUSEQ = r'\+='
t_MINUSEQ = r'-='
t_TIMESEQ = r'\*='
t_DIVEQ = r'/='
t_MODEQ = r'%='
t_PLUSPLUS = r'\+\+'
t_MINUSMINUS = r'--'
t_SEMI = r';'
t_GT = r'>'
t_LT = r'<'
t_GE = r'>='
t_LE = r'<='
t_EQ = r'=='
t_NE = r'!='
t_ignore = ' \t'


def t_newline(t):
    r'\n+'
    t.lexer.lineno += len(t.value)


def t_NUMBER(t):
    r'\d+(\.\d+)?'
    t.value = float(t.value) if '.' in t.value else int(t.value)
    return t


def t_STRING(t):
    r'"[^"]*"'
    t.value = t.value[1:-1]
    return t


def t_NAME(t):
    r'[a-zA-Z_][a-zA-Z0-9_]*'
    t.type = reserved.get(t.value, 'IDENTIFIER')
    return t


def t_error(t):
    print(f"Illegal character '{t.value[0]}'")
    t.lexer.skip(1)


lexer = lex.lex()

# --- Parser ---
#
# Every 'expr', 'cond', and 'statement' rule below produces a zero-arg
# callable (a "thunk") rather than a concrete value. This defers actual
# evaluation until the thunk is invoked, which is required for correctness
# once control flow (if/else, for) can execute a branch/body more than
# once, or not at all, based on a condition re-checked each time.

symtab = {}

precedence = (
    ('left', 'PLUS', 'MINUS'),
    ('left', 'TIMES', 'DIVIDE', 'MODULO'),
)

_BIN_OPS = {
    '+': operator.add,
    '-': operator.sub,
    '*': operator.mul,
    '/': operator.truediv,
    '%': operator.mod,
}

_CMP_OPS = {
    '>': operator.gt,
    '<': operator.lt,
    '>=': operator.ge,
    '<=': operator.le,
    '==': operator.eq,
    '!=': operator.ne,
}


def p_assignment(p):
    'assignment : IDENTIFIER EQUALS expr'
    name, value_thunk = p[1], p[3]
    p[0] = lambda: symtab.update({name: value_thunk()})


def p_assignment_compound(p):
    '''assignment : IDENTIFIER PLUSEQ expr
                   | IDENTIFIER MINUSEQ expr
                   | IDENTIFIER TIMESEQ expr
                   | IDENTIFIER DIVEQ expr
                   | IDENTIFIER MODEQ expr'''
    name, base_op, value_thunk = p[1], p[2][0], p[3]

    def _compound_assign():
        if name not in symtab:
            print(f"Undefined variable '{name}'")
            return
        symtab[name] = _BIN_OPS[base_op](symtab[name], value_thunk())

    p[0] = _compound_assign


def p_assignment_incdec(p):
    '''assignment : IDENTIFIER PLUSPLUS
                   | IDENTIFIER MINUSMINUS'''
    name, delta = p[1], (1 if p[2] == '++' else -1)

    def _incdec():
        if name not in symtab:
            print(f"Undefined variable '{name}'")
            return
        symtab[name] = symtab[name] + delta

    p[0] = _incdec


def p_statement_assign(p):
    'statement : assignment SEMI'
    p[0] = p[1]


def p_statement_expr(p):
    'statement : expr SEMI'
    value_thunk = p[1]
    p[0] = lambda: value_thunk()


def p_statement_print(p):
    'statement : PRINT LPAREN expr RPAREN SEMI'
    value_thunk = p[3]
    p[0] = lambda: print(value_thunk())


def p_statement_if(p):
    'statement : IF LPAREN cond RPAREN statement'
    cond_thunk, then_branch = p[3], p[5]
    p[0] = lambda: then_branch() if cond_thunk() else None


def p_statement_if_else(p):
    'statement : IF LPAREN cond RPAREN statement ELSE statement'
    cond_thunk, then_branch, else_branch = p[3], p[5], p[7]
    p[0] = lambda: then_branch() if cond_thunk() else else_branch()


def p_statement_for(p):
    'statement : FOR LPAREN assignment SEMI cond SEMI assignment RPAREN statement'
    init, cond_thunk, update, body = p[3], p[5], p[7], p[9]

    def _run_for():
        init()
        while cond_thunk():
            body()
            update()

    p[0] = _run_for


def p_statement_while(p):
    'statement : WHILE LPAREN cond RPAREN statement'
    cond_thunk, body = p[3], p[5]

    def _run_while():
        while cond_thunk():
            body()

    p[0] = _run_while


def p_statement_do_while(p):
    'statement : DO statement WHILE LPAREN cond RPAREN SEMI'
    body, cond_thunk = p[2], p[5]

    def _run_do_while():
        while True:
            body()
            if not cond_thunk():
                break

    p[0] = _run_do_while


def p_statement_block(p):
    'statement : LBRACE stmtlist RBRACE'
    stmts = p[2]

    def _run_block():
        for stmt in stmts:
            stmt()

    p[0] = _run_block


def p_stmtlist_one(p):
    'stmtlist : statement'
    p[0] = [p[1]]


def p_stmtlist_many(p):
    'stmtlist : stmtlist statement'
    p[0] = p[1] + [p[2]]


def p_cond(p):
    '''cond : expr GT expr
            | expr LT expr
            | expr GE expr
            | expr LE expr
            | expr EQ expr
            | expr NE expr'''
    left, op, right = p[1], p[2], p[3]
    p[0] = lambda: _CMP_OPS[op](left(), right())


def p_expr_binop(p):
    '''expr : expr PLUS expr
             | expr MINUS expr
             | expr TIMES expr
             | expr DIVIDE expr
             | expr MODULO expr'''
    left, op, right = p[1], p[2], p[3]
    p[0] = lambda: _BIN_OPS[op](left(), right())


def p_expr_group(p):
    'expr : LPAREN expr RPAREN'
    p[0] = p[2]


def p_expr_sqrt(p):
    'expr : SQRT LPAREN expr RPAREN'
    inner = p[3]
    p[0] = lambda: math.sqrt(inner())


def p_expr_pow(p):
    'expr : POW LPAREN expr COMMA expr RPAREN'
    base, exponent = p[3], p[5]
    p[0] = lambda: math.pow(base(), exponent())


def p_expr_concat(p):
    'expr : CONCAT LPAREN arglist RPAREN'
    args = p[3]
    p[0] = lambda: ''.join(str(arg()) for arg in args)


def p_arglist_one(p):
    'arglist : expr'
    p[0] = [p[1]]


def p_arglist_many(p):
    'arglist : arglist COMMA expr'
    p[0] = p[1] + [p[3]]


def p_expr_number(p):
    'expr : NUMBER'
    value = p[1]
    p[0] = lambda: value


def p_expr_string(p):
    'expr : STRING'
    value = p[1]
    p[0] = lambda: value


def p_expr_identifier(p):
    'expr : IDENTIFIER'
    name = p[1]

    def _lookup():
        if name not in symtab:
            print(f"Undefined variable '{name}'")
            return None
        return symtab[name]

    p[0] = _lookup


def p_error(p):
    if p:
        print(f"Syntax error at '{p.value}'")
    else:
        print("Syntax error at EOF")


parser = yacc.yacc(start='statement')

if __name__ == '__main__':
    while True:
        try:
            line = input('calc> ')
        except EOFError:
            break
        if not line.strip():
            continue
        buffer = line
        while buffer.count('{') > buffer.count('}') or not buffer.rstrip().endswith((';', '}')):
            try:
                buffer += '\n' + input('...   ')
            except EOFError:
                break
        thunk = parser.parse(buffer, lexer=lexer)
        if thunk is not None:
            result = thunk()
            if result is not None:
                print(result)
