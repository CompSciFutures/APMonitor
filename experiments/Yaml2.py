#!/usr/bin/env python3
"""Pyl-python: dynamic YAML parser (load_dynamic_yaml).

Standalone recursive-descent parser — does not use PyYAML to parse.
yaml.YAMLError is used only as the base class for this module's own
exception, per project convention (yaml library reserved for
exceptions).

Contract: every scalar is returned as a string with its original
quoting preserved verbatim (e.g. '"hello"' stays '"hello"', hello
stays hello), so callers can re-interpret values downstream. Mappings
and sequences are returned as dict / list respectively. A null/empty
value is represented as "".

Supported: block mappings, block sequences (including "- key: value"
compact form), flow mappings/sequences (may span lines), single- and
double-quoted scalars, plain scalars, block scalars (| literal, >
folded, with -/+ chomping and explicit indent indicators), comments,
anchors (&name) and aliases (*name), tab-in-indentation detection,
duplicate-key detection.

Known limitations (flagged, not silently mishandled):
  - Single YAML document only; `---` document-start markers are
    skipped but a second document raises an error.
  - Folded (>) block scalars fold every line break to a space; the
    "more-indented lines stay literal" and "blank line separates
    paragraphs" nuances of the spec are not implemented.
  - Explicit tags (!!str etc.) are not resolved/stripped - a leading
    tag token will be treated as part of a plain scalar.
  - The "sequence item at the same indent as its parent dash" quirk
    (legal in the YAML spec) is not supported; nested content must be
    indented strictly further than the dash.
  - Flow-collection duplicate-key and syntax errors report the line
    where the collection opened, not the exact sub-line.
"""

import copy
import re
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml  # exceptions only

Node = Union[Dict[str, Any], List[Any], str]


class YamlSyntaxError(yaml.YAMLError):
    def __init__(self, message: str, line: int):
        self.line = line
        super().__init__(f"line {line}: {message}")


# --------------------------------------------------------------------------
# Low-level line helpers
# --------------------------------------------------------------------------

_LEADING_WS_RE = re.compile(r"[ \t]*")


def _indent_of(line: str, line_no: int) -> int:
    leading = _LEADING_WS_RE.match(line).group()
    if "\t" in leading:
        raise YamlSyntaxError("tab character in indentation", line_no)
    return len(leading)


def _strip_comment(line: str) -> str:
    """Quote-aware comment stripping: '#' starts a comment only outside
    quotes and only when at line start or preceded by whitespace."""
    in_dquote = in_squote = False
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if in_dquote:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == '"':
                in_dquote = False
            i += 1
            continue
        if in_squote:
            if c == "'":
                if i + 1 < n and line[i + 1] == "'":
                    i += 2
                    continue
                in_squote = False
            i += 1
            continue
        if c == '"':
            in_dquote = True
        elif c == "'":
            in_squote = True
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
        i += 1
    return line


def _consume_quoted(text: str, start: int, line_no: int) -> Tuple[str, int]:
    """Returns (quoted_text_including_quotes, index_after_closing_quote)."""
    q = text[start]
    i, n = start + 1, len(text)
    if q == '"':
        while i < n:
            c = text[i]
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == '"':
                return text[start:i + 1], i + 1
            i += 1
    else:
        while i < n:
            c = text[i]
            if c == "'":
                if i + 1 < n and text[i + 1] == "'":
                    i += 2
                    continue
                return text[start:i + 1], i + 1
            i += 1
    raise YamlSyntaxError("unterminated quoted scalar", line_no)


def _split_key(content: str, line_no: int) -> Optional[Tuple[str, str]]:
    """If content is a mapping-key line, returns (key, rest); else None."""
    if content and content[0] in "\"'":
        key_text, after = _consume_quoted(content, 0, line_no)
        rest = content[after:].lstrip()
        if rest == ":" or rest.startswith(": ") or rest.startswith(":\t"):
            return key_text, rest[1:].strip()
        return None
    in_dquote = in_squote = False
    i, n = 0, len(content)
    while i < n:
        c = content[i]
        if in_dquote:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == '"':
                in_dquote = False
            i += 1
            continue
        if in_squote:
            if c == "'":
                if i + 1 < n and content[i + 1] == "'":
                    i += 2
                    continue
                in_squote = False
            i += 1
            continue
        if c == '"':
            in_dquote = True
        elif c == "'":
            in_squote = True
        elif c == ":" and (i + 1 == n or content[i + 1] in " \t"):
            return content[:i].strip(), content[i + 1:].strip()
        i += 1
    return None


def _is_seq_item(content: str) -> bool:
    return content == "-" or content.startswith("- ") or content.startswith("-\t")


def _parse_scalar_token(text: str, line_no: int) -> str:
    if text[0] in "\"'":
        quoted, end = _consume_quoted(text, 0, line_no)
        if end != len(text):
            raise YamlSyntaxError(
                f"trailing content after quoted scalar: {text[end:]!r}", line_no
            )
        return quoted
    return text


# --------------------------------------------------------------------------
# Cursor
# --------------------------------------------------------------------------

class _Cursor:
    def __init__(self, lines: List[str]):
        self.lines = lines
        self.i = 0
        self.n = len(lines)

    def raw(self) -> str:
        return self.lines[self.i]

    def at_end(self) -> bool:
        return self.i >= self.n

    def advance(self) -> None:
        self.i += 1

    def line_no(self) -> int:
        return self.i + 1


def _next_significant(cursor: _Cursor) -> bool:
    """Advances past blank/comment-only lines. Returns False at EOF."""
    while not cursor.at_end():
        raw = cursor.raw()
        _indent_of(raw, cursor.line_no())  # tab check
        if _strip_comment(raw).strip() == "":
            cursor.advance()
            continue
        return True
    return False


# --------------------------------------------------------------------------
# Block parsing
# --------------------------------------------------------------------------

def debug_dump_yaml(node: Node) -> None:
    """Prints the parsed tree, each scalar verbatim (quotes as stored)."""
    _dump(node, 0)


def _dump(node: Node, indent: int) -> None:
    prefix = "  " * indent
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, (dict, list)):
                print(f"{prefix}{key}:")
                _dump(value, indent + 1)
            else:
                print(f"{prefix}{key}: {value}")
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, (dict, list)):
                print(f"{prefix}-")
                _dump(item, indent + 1)
            else:
                print(f"{prefix}- {item}")
    else:
        print(f"{prefix}{node}")


def load_dynamic_yaml_document(name: str) -> Node:
    """Reads the file at `name` and parses its contents."""
    with open(name, "r", encoding="utf-8") as f:
        text = f.read()
    return load_dynamic_yaml(text)


def load_dynamic_yaml(text: str) -> Node:
    cursor = _Cursor(text.splitlines())
    anchors: Dict[str, Node] = {}
    if not _next_significant(cursor):
        return ""
    indent = _indent_of(cursor.raw(), cursor.line_no())
    value = _parse_block(cursor, indent, anchors)
    if _next_significant(cursor):
        raise YamlSyntaxError(
            "unexpected content (multiple documents not supported)", cursor.line_no()
        )
    return value


def _parse_block(cursor: _Cursor, indent: int, anchors: Dict[str, Node]) -> Node:
    raw = cursor.raw()
    content = _strip_comment(raw).strip()
    if content == "---":
        cursor.advance()
        if not _next_significant(cursor):
            return ""
        return _parse_block(cursor, _indent_of(cursor.raw(), cursor.line_no()), anchors)
    if _is_seq_item(content):
        return _parse_sequence(cursor, indent, anchors)
    split = _split_key(content, cursor.line_no())
    if split is not None:
        return _parse_mapping(cursor, indent, anchors)
    line_no = cursor.line_no()
    cursor.advance()
    return _resolve_rest(cursor, indent, content, anchors, line_no)


def _parse_mapping(cursor: _Cursor, indent: int, anchors: Dict[str, Node]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    while True:
        if not _next_significant(cursor):
            break
        raw = cursor.raw()
        if _indent_of(raw, cursor.line_no()) != indent:
            break
        content = _strip_comment(raw).strip()
        split = _split_key(content, cursor.line_no())
        if split is None:
            break
        key, rest = split
        line_no = cursor.line_no()
        cursor.advance()
        value = _resolve_rest(cursor, indent, rest, anchors, line_no)
        if key in result:
            raise YamlSyntaxError(f"duplicate key {key!r}", line_no)
        result[key] = value
    return result


def _parse_sequence(cursor: _Cursor, indent: int, anchors: Dict[str, Node]) -> List[Node]:
    result: List[Node] = []
    while True:
        if not _next_significant(cursor):
            break
        raw = cursor.raw()
        if _indent_of(raw, cursor.line_no()) != indent:
            break
        content = _strip_comment(raw).strip()
        if not _is_seq_item(content):
            break
        line_no = cursor.line_no()
        cursor.advance()
        if content == "-":
            rest, dash_col = "", indent + 1
        else:
            rest, dash_col = content[2:], indent + 2
        item = _resolve_rest(cursor, indent, rest, anchors, line_no, dash_col=dash_col)
        result.append(item)
    return result


def _parse_inline_mapping(
    cursor: _Cursor,
    dash_col: int,
    first_key: str,
    first_rest: str,
    anchors: Dict[str, Node],
    line_no: int,
) -> Dict[str, str]:
    result: Dict[str, str] = {}
    result[first_key] = _resolve_rest(cursor, dash_col, first_rest, anchors, line_no)
    while True:
        if not _next_significant(cursor):
            break
        raw = cursor.raw()
        if _indent_of(raw, cursor.line_no()) != dash_col:
            break
        content = _strip_comment(raw).strip()
        split = _split_key(content, cursor.line_no())
        if split is None:
            break
        key, rest = split
        entry_line_no = cursor.line_no()
        cursor.advance()
        if key in result:
            raise YamlSyntaxError(f"duplicate key {key!r}", entry_line_no)
        result[key] = _resolve_rest(cursor, dash_col, rest, anchors, entry_line_no)
    return result


_BLOCK_SCALAR_HEADER_RE = re.compile(r"^([|>])([+-]?)(\d*)$")


def _resolve_rest(
    cursor: _Cursor,
    own_indent: int,
    rest: str,
    anchors: Dict[str, Node],
    line_no: int,
    dash_col: Optional[int] = None,
) -> Node:
    rest = rest.strip()

    if rest.startswith("&"):
        m = re.match(r"&(\S+)\s*(.*)", rest)
        anchor_name, remainder = m.group(1), m.group(2)
        value = _resolve_rest(cursor, own_indent, remainder, anchors, line_no, dash_col)
        anchors[anchor_name] = value
        return value

    if rest.startswith("*"):
        alias_name = rest[1:].strip()
        if alias_name not in anchors:
            raise YamlSyntaxError(f"undefined alias {alias_name!r}", line_no)
        return copy.deepcopy(anchors[alias_name])

    header_match = _BLOCK_SCALAR_HEADER_RE.match(rest)
    if header_match:
        return _parse_block_scalar(cursor, own_indent, header_match, line_no)

    if rest.startswith("{") or rest.startswith("["):
        text = _gather_flow_text(cursor, rest, line_no)
        return _FlowParser(text, line_no).parse()

    if rest == "":
        if not _next_significant(cursor):
            return ""
        nxt_indent = _indent_of(cursor.raw(), cursor.line_no())
        if nxt_indent <= own_indent:
            return ""
        return _parse_block(cursor, nxt_indent, anchors)

    if dash_col is not None:
        split = _split_key(rest, line_no)
        if split is not None:
            key, first_rest = split
            return _parse_inline_mapping(cursor, dash_col, key, first_rest, anchors, line_no)

    return _parse_scalar_token(rest, line_no)


# --------------------------------------------------------------------------
# Block scalars (| and >)
# --------------------------------------------------------------------------

def _parse_block_scalar(cursor: _Cursor, own_indent: int, header_match, line_no: int) -> str:
    style, chomp, explicit_str = header_match.group(1), header_match.group(2), header_match.group(3)
    explicit_indent = own_indent + int(explicit_str) if explicit_str else None

    lines: List[str] = []
    block_indent: Optional[int] = explicit_indent
    while not cursor.at_end():
        raw = cursor.raw()
        if raw.strip() == "":
            lines.append("")
            cursor.advance()
            continue
        cur_indent = _indent_of(raw, cursor.line_no())
        if cur_indent <= own_indent:
            break
        if block_indent is None:
            block_indent = cur_indent
        if cur_indent < block_indent:
            break
        lines.append(raw[block_indent:])
        cursor.advance()

    trailing_blanks = 0
    while lines and lines[-1] == "":
        lines.pop()
        trailing_blanks += 1

    body = "\n".join(lines) if style == "|" else " ".join(lines)

    if chomp == "+":
        if lines:
            body += "\n"
        body += "\n" * trailing_blanks
    elif chomp == "-":
        pass
    else:  # clip (default)
        if lines:
            body += "\n"

    return body


# --------------------------------------------------------------------------
# Flow collections ({...} / [...]), possibly spanning multiple lines
# --------------------------------------------------------------------------

def _gather_flow_text(cursor: _Cursor, initial: str, line_no: int) -> str:
    text = initial
    i = 0
    depth = 0
    started = False
    in_dquote = in_squote = False
    while True:
        while i < len(text):
            c = text[i]
            if in_dquote:
                if c == "\\" and i + 1 < len(text):
                    i += 2
                    continue
                if c == '"':
                    in_dquote = False
                i += 1
                continue
            if in_squote:
                if c == "'":
                    if i + 1 < len(text) and text[i + 1] == "'":
                        i += 2
                        continue
                    in_squote = False
                i += 1
                continue
            if c == '"':
                in_dquote = True
            elif c == "'":
                in_squote = True
            elif c in "{[":
                depth += 1
                started = True
            elif c in "}]":
                depth -= 1
            i += 1
        if started and depth == 0:
            return text
        if cursor.at_end():
            raise YamlSyntaxError("unterminated flow collection", line_no)
        nxt = _strip_comment(cursor.raw()).strip()
        cursor.advance()
        text += " " + nxt


class _FlowParser:
    def __init__(self, text: str, line_no: int):
        self.s = text
        self.i = 0
        self.n = len(text)
        self.line_no = line_no

    def parse(self) -> Node:
        self._skip_ws()
        return self._parse_value()

    def _skip_ws(self) -> None:
        while self.i < self.n and self.s[self.i] in " \t\n":
            self.i += 1

    def _parse_value(self) -> Node:
        self._skip_ws()
        c = self.s[self.i]
        if c == "{":
            return self._parse_map()
        if c == "[":
            return self._parse_seq()
        if c in "\"'":
            return self._parse_quoted()
        return self._parse_plain()

    def _parse_map(self) -> Dict[str, Node]:
        self.i += 1
        result: Dict[str, Node] = {}
        self._skip_ws()
        if self.i < self.n and self.s[self.i] == "}":
            self.i += 1
            return result
        while True:
            self._skip_ws()
            key = self._parse_quoted() if self.s[self.i] in "\"'" else self._parse_plain(stop_at_colon=True)
            self._skip_ws()
            if self.i >= self.n or self.s[self.i] != ":":
                raise YamlSyntaxError("expected ':' in flow mapping", self.line_no)
            self.i += 1
            self._skip_ws()
            val = self._parse_value()
            if key in result:
                raise YamlSyntaxError(f"duplicate key {key!r} in flow mapping", self.line_no)
            result[key] = val
            self._skip_ws()
            if self.i < self.n and self.s[self.i] == ",":
                self.i += 1
                continue
            if self.i < self.n and self.s[self.i] == "}":
                self.i += 1
                break
            raise YamlSyntaxError("malformed flow mapping", self.line_no)
        return result

    def _parse_seq(self) -> List[Node]:
        self.i += 1
        result: List[Node] = []
        self._skip_ws()
        if self.i < self.n and self.s[self.i] == "]":
            self.i += 1
            return result
        while True:
            result.append(self._parse_value())
            self._skip_ws()
            if self.i < self.n and self.s[self.i] == ",":
                self.i += 1
                self._skip_ws()
                continue
            if self.i < self.n and self.s[self.i] == "]":
                self.i += 1
                break
            raise YamlSyntaxError("malformed flow sequence", self.line_no)
        return result

    def _parse_quoted(self) -> str:
        q = self.s[self.i]
        start = self.i
        self.i += 1
        if q == '"':
            while self.i < self.n:
                c = self.s[self.i]
                if c == "\\" and self.i + 1 < self.n:
                    self.i += 2
                    continue
                if c == '"':
                    self.i += 1
                    break
                self.i += 1
        else:
            while self.i < self.n:
                c = self.s[self.i]
                if c == "'":
                    if self.i + 1 < self.n and self.s[self.i + 1] == "'":
                        self.i += 2
                        continue
                    self.i += 1
                    break
                self.i += 1
        return self.s[start:self.i]

    def _parse_plain(self, stop_at_colon: bool = False) -> str:
        start = self.i
        stops = ",{}[]" + (":" if stop_at_colon else "")
        while self.i < self.n and self.s[self.i] not in stops:
            self.i += 1
        return self.s[start:self.i].strip()