use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::error::{EngineError, EngineResult};
use crate::resp::{
    parse_f64_bytes, parse_i64_bytes, write_array_header, write_bulk_string, write_integer,
    write_null,
};
use crate::storage::hashtable::RawHashTable;
use crate::storage::{SetCondition, StorageEngine};

pub const DEFAULT_VM_MAX_STEPS: usize = 100_000;

// ==================== PURE-RUST FIPS 180-4 SHA-256 ====================

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(((data.len() + 9 + 63) / 64) * 64);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in padded.chunks_exact(64) {
        for i in 0..16 {
            let off = i * 4;
            w[i] = u32::from_be_bytes([chunk[off], chunk[off + 1], chunk[off + 2], chunk[off + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut digest = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        let bytes = word.to_be_bytes();
        digest[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    digest
}

pub fn sha256_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = sha256(data);
    let mut out = String::with_capacity(64);
    for &b in &digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

// ==================== EMBEDDED BYTECODE COMPILER & VM ====================

#[derive(Clone, Debug, PartialEq)]
pub enum VmValue {
    Null,
    Bool(bool),
    Int(i64),
    Str(Vec<u8>),
    Array(Vec<VmValue>),
}

impl VmValue {
    pub fn is_truthy(&self) -> bool {
        match self {
            VmValue::Null => false,
            VmValue::Bool(b) => *b,
            VmValue::Int(n) => *n != 0,
            VmValue::Str(s) => !s.is_empty(),
            VmValue::Array(a) => !a.is_empty(),
        }
    }

    pub fn to_arg_bytes(&self) -> Vec<u8> {
        match self {
            VmValue::Null => Vec::new(),
            VmValue::Bool(b) => if *b { b"1".to_vec() } else { b"0".to_vec() },
            VmValue::Int(n) => n.to_string().into_bytes(),
            VmValue::Str(s) => s.clone(),
            VmValue::Array(a) => format!("[array:{}]", a.len()).into_bytes(),
        }
    }

    pub fn as_int(&self) -> EngineResult<i64> {
        match self {
            VmValue::Int(n) => Ok(*n),
            VmValue::Bool(b) => Ok(i64::from(*b)),
            VmValue::Str(s) => parse_i64_bytes(s),
            VmValue::Null => Ok(0),
            VmValue::Array(_) => Err(EngineError::InvalidArgument(
                "VM cannot coerce Array to integer".to_string(),
            )),
        }
    }

    pub fn write_resp(&self, out: &mut Vec<u8>) {
        self.serialize_resp(out);
    }

    pub fn serialize_resp(&self, out: &mut Vec<u8>) {
        match self {
            VmValue::Null => write_null(out),
            VmValue::Bool(b) => write_integer(out, i64::from(*b)),
            VmValue::Int(n) => write_integer(out, *n),
            VmValue::Str(s) => write_bulk_string(out, s),
            VmValue::Array(items) => {
                write_array_header(out, items.len());
                for it in items {
                    it.serialize_resp(out);
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
enum OpCode {
    PushNull,
    PushBool(bool),
    PushInt(i64),
    PushStr(Box<[u8]>),
    LoadLocal(usize),
    StoreLocal(usize),
    LoadKey,
    LoadArg,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Neg,
    Not,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    ToNumber,
    ToString,
    HostCall(usize),
    Jump(usize),
    JumpIfFalse(usize),
    Pop,
    Return,
}

#[derive(Clone, Debug)]
pub struct CompiledScript {
    code: Vec<OpCode>,
    num_locals: usize,
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Int(i64),
    Str(Vec<u8>),
    Ident(String),
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Semi,
    Dot,
    Concat,
    Assign,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Bang,
    Eof,
}

fn lex_script(src: &[u8]) -> EngineResult<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut i = 0usize;

    while i < src.len() {
        let c = src[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // Comments: `// ...` or Lua `-- ...`
        if (c == b'/' && i + 1 < src.len() && src[i + 1] == b'/')
            || (c == b'-' && i + 1 < src.len() && src[i + 1] == b'-')
        {
            while i < src.len() && src[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        if c == b'"' || c == b'\'' {
            let quote = c;
            i += 1;
            let mut s = Vec::new();
            while i < src.len() && src[i] != quote {
                if src[i] == b'\\' && i + 1 < src.len() {
                    i += 1;
                    match src[i] {
                        b'n' => s.push(b'\n'),
                        b'r' => s.push(b'\r'),
                        b't' => s.push(b'\t'),
                        other => s.push(other),
                    }
                } else {
                    s.push(src[i]);
                }
                i += 1;
            }
            if i >= src.len() {
                return Err(EngineError::InvalidArgument(
                    "VM syntax error: unterminated string literal".to_string(),
                ));
            }
            i += 1;
            tokens.push(Token::Str(s));
            continue;
        }

        if c.is_ascii_digit() {
            let start = i;
            while i < src.len() && src[i].is_ascii_digit() {
                i += 1;
            }
            let val = parse_i64_bytes(&src[start..i])?;
            tokens.push(Token::Int(val));
            continue;
        }

        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < src.len() && (src[i].is_ascii_alphanumeric() || src[i] == b'_') {
                i += 1;
            }
            let word = std::str::from_utf8(&src[start..i])?.to_string();
            match word.as_str() {
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                "not" => tokens.push(Token::Bang),
                _ => tokens.push(Token::Ident(word)),
            }
            continue;
        }

        match c {
            b'(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            b')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            b'{' => {
                tokens.push(Token::LBrace);
                i += 1;
            }
            b'}' => {
                tokens.push(Token::RBrace);
                i += 1;
            }
            b'[' => {
                tokens.push(Token::LBracket);
                i += 1;
            }
            b']' => {
                tokens.push(Token::RBracket);
                i += 1;
            }
            b',' => {
                tokens.push(Token::Comma);
                i += 1;
            }
            b';' => {
                tokens.push(Token::Semi);
                i += 1;
            }
            b'.' => {
                if i + 1 < src.len() && src[i + 1] == b'.' {
                    tokens.push(Token::Concat);
                    i += 2;
                } else {
                    tokens.push(Token::Dot);
                    i += 1;
                }
            }
            b'+' => {
                tokens.push(Token::Plus);
                i += 1;
            }
            b'-' => {
                tokens.push(Token::Minus);
                i += 1;
            }
            b'*' => {
                tokens.push(Token::Star);
                i += 1;
            }
            b'/' => {
                tokens.push(Token::Slash);
                i += 1;
            }
            b'%' => {
                tokens.push(Token::Percent);
                i += 1;
            }
            b'=' => {
                if i + 1 < src.len() && src[i + 1] == b'=' {
                    tokens.push(Token::EqEq);
                    i += 2;
                } else {
                    tokens.push(Token::Assign);
                    i += 1;
                }
            }
            b'!' => {
                if i + 1 < src.len() && src[i + 1] == b'=' {
                    tokens.push(Token::NotEq);
                    i += 2;
                } else {
                    tokens.push(Token::Bang);
                    i += 1;
                }
            }
            b'~' if i + 1 < src.len() && src[i + 1] == b'=' => {
                tokens.push(Token::NotEq);
                i += 2;
            }
            b'<' => {
                if i + 1 < src.len() && src[i + 1] == b'=' {
                    tokens.push(Token::Le);
                    i += 2;
                } else {
                    tokens.push(Token::Lt);
                    i += 1;
                }
            }
            b'>' => {
                if i + 1 < src.len() && src[i + 1] == b'=' {
                    tokens.push(Token::Ge);
                    i += 2;
                } else {
                    tokens.push(Token::Gt);
                    i += 1;
                }
            }
            b'&' if i + 1 < src.len() && src[i + 1] == b'&' => {
                tokens.push(Token::And);
                i += 2;
            }
            b'|' if i + 1 < src.len() && src[i + 1] == b'|' => {
                tokens.push(Token::Or);
                i += 2;
            }
            other => {
                return Err(EngineError::InvalidArgument(format!(
                    "VM syntax error: unexpected character '{}'",
                    other as char
                )))
            }
        }
    }

    tokens.push(Token::Eof);
    Ok(tokens)
}

struct Compiler {
    tokens: Vec<Token>,
    pos: usize,
    locals: Vec<String>,
    code: Vec<OpCode>,
}

impl Compiler {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            pos: 0,
            locals: Vec::new(),
            code: Vec::new(),
        }
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        let tok = self.peek().clone();
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    fn expect_token(&mut self, expected: &Token) -> EngineResult<()> {
        let actual = self.advance();
        if &actual == expected {
            Ok(())
        } else {
            Err(EngineError::InvalidArgument(format!(
                "VM syntax error: expected {:?}, found {:?}",
                expected, actual
            )))
        }
    }

    fn resolve_or_declare_local(&mut self, name: &str) -> usize {
        if let Some(idx) = self.locals.iter().position(|n| n == name) {
            idx
        } else {
            let idx = self.locals.len();
            self.locals.push(name.to_string());
            idx
        }
    }

    fn is_block_terminator(&self) -> bool {
        matches!(self.peek(), Token::Eof | Token::RBrace)
            || matches!(self.peek(), Token::Ident(w) if w == "end" || w == "else" || w == "elseif")
    }

    fn compile_program(&mut self) -> EngineResult<()> {
        while !matches!(self.peek(), Token::Eof) {
            self.compile_stmt()?;
        }
        self.code.push(OpCode::PushNull);
        self.code.push(OpCode::Return);
        Ok(())
    }

    fn compile_stmt(&mut self) -> EngineResult<()> {
        while matches!(self.peek(), Token::Semi) {
            self.advance();
        }
        match self.peek().clone() {
            Token::Ident(kw) if kw == "let" || kw == "local" => {
                self.advance();
                let Token::Ident(var_name) = self.advance() else {
                    return Err(EngineError::InvalidArgument(
                        "VM syntax error: expected identifier after let/local".to_string(),
                    ));
                };
                let slot = self.resolve_or_declare_local(&var_name);
                if matches!(self.peek(), Token::Assign) {
                    self.advance();
                    self.compile_expr()?;
                } else {
                    self.code.push(OpCode::PushNull);
                }
                self.code.push(OpCode::StoreLocal(slot));
                if matches!(self.peek(), Token::Semi) {
                    self.advance();
                }
                Ok(())
            }
            Token::Ident(kw) if kw == "return" => {
                self.advance();
                if matches!(self.peek(), Token::Semi | Token::Eof | Token::RBrace)
                    || matches!(self.peek(), Token::Ident(w) if w == "end" || w == "else")
                {
                    self.code.push(OpCode::PushNull);
                } else {
                    self.compile_expr()?;
                }
                if matches!(self.peek(), Token::Semi) {
                    self.advance();
                }
                self.code.push(OpCode::Return);
                Ok(())
            }
            Token::Ident(kw) if kw == "if" => self.compile_if(),
            Token::Ident(kw) if kw == "while" => self.compile_while(),
            Token::Ident(name) => {
                if self.tokens.get(self.pos + 1) == Some(&Token::Assign) {
                    self.advance();
                    self.advance();
                    self.compile_expr()?;
                    let slot = self.resolve_or_declare_local(&name);
                    self.code.push(OpCode::StoreLocal(slot));
                    if matches!(self.peek(), Token::Semi) {
                        self.advance();
                    }
                    Ok(())
                } else {
                    self.compile_expr()?;
                    self.code.push(OpCode::Pop);
                    if matches!(self.peek(), Token::Semi) {
                        self.advance();
                    }
                    Ok(())
                }
            }
            _ => {
                self.compile_expr()?;
                self.code.push(OpCode::Pop);
                if matches!(self.peek(), Token::Semi) {
                    self.advance();
                }
                Ok(())
            }
        }
    }

    fn compile_if(&mut self) -> EngineResult<()> {
        self.advance(); // consume `if` or `elseif`
        self.compile_expr()?;

        let uses_braces = if matches!(self.peek(), Token::Ident(w) if w == "then") {
            self.advance();
            false
        } else {
            self.expect_token(&Token::LBrace)?;
            true
        };

        let jump_false_idx = self.code.len();
        self.code.push(OpCode::JumpIfFalse(0));

        while !self.is_block_terminator() {
            self.compile_stmt()?;
        }

        if uses_braces {
            self.expect_token(&Token::RBrace)?;
            if matches!(self.peek(), Token::Ident(w) if w == "else") {
                self.advance();
                let jump_end_idx = self.code.len();
                self.code.push(OpCode::Jump(0));
                self.code[jump_false_idx] = OpCode::JumpIfFalse(self.code.len());

                if matches!(self.peek(), Token::Ident(w) if w == "if") {
                    self.compile_if()?;
                } else {
                    self.expect_token(&Token::LBrace)?;
                    while !self.is_block_terminator() {
                        self.compile_stmt()?;
                    }
                    self.expect_token(&Token::RBrace)?;
                }
                self.code[jump_end_idx] = OpCode::Jump(self.code.len());
            } else {
                self.code[jump_false_idx] = OpCode::JumpIfFalse(self.code.len());
            }
        } else if matches!(self.peek(), Token::Ident(w) if w == "elseif") {
            let jump_end_idx = self.code.len();
            self.code.push(OpCode::Jump(0));
            self.code[jump_false_idx] = OpCode::JumpIfFalse(self.code.len());
            self.compile_if()?;
            self.code[jump_end_idx] = OpCode::Jump(self.code.len());
        } else if matches!(self.peek(), Token::Ident(w) if w == "else") {
            self.advance();
            let jump_end_idx = self.code.len();
            self.code.push(OpCode::Jump(0));
            self.code[jump_false_idx] = OpCode::JumpIfFalse(self.code.len());
            while !self.is_block_terminator() {
                self.compile_stmt()?;
            }
            self.expect_token(&Token::Ident("end".to_string()))?;
            self.code[jump_end_idx] = OpCode::Jump(self.code.len());
        } else {
            self.expect_token(&Token::Ident("end".to_string()))?;
            self.code[jump_false_idx] = OpCode::JumpIfFalse(self.code.len());
        }
        Ok(())
    }

    fn compile_while(&mut self) -> EngineResult<()> {
        self.advance(); // consume `while`
        let loop_start = self.code.len();
        self.compile_expr()?;

        let uses_braces = if matches!(self.peek(), Token::Ident(w) if w == "do") {
            self.advance();
            false
        } else {
            self.expect_token(&Token::LBrace)?;
            true
        };

        let exit_jump = self.code.len();
        self.code.push(OpCode::JumpIfFalse(0));

        while !self.is_block_terminator() {
            self.compile_stmt()?;
        }

        if uses_braces {
            self.expect_token(&Token::RBrace)?;
        } else {
            self.expect_token(&Token::Ident("end".to_string()))?;
        }

        self.code.push(OpCode::Jump(loop_start));
        self.code[exit_jump] = OpCode::JumpIfFalse(self.code.len());
        Ok(())
    }

    fn compile_expr(&mut self) -> EngineResult<()> {
        self.compile_or()
    }

    fn compile_or(&mut self) -> EngineResult<()> {
        self.compile_and()?;
        while matches!(self.peek(), Token::Or) {
            self.advance();
            // Short-circuit style boolean OR
            let j_false = self.code.len();
            self.code.push(OpCode::JumpIfFalse(0));
            self.code.push(OpCode::PushBool(true));
            let j_end = self.code.len();
            self.code.push(OpCode::Jump(0));
            self.code[j_false] = OpCode::JumpIfFalse(self.code.len());
            self.compile_and()?;
            self.code[j_end] = OpCode::Jump(self.code.len());
        }
        Ok(())
    }

    fn compile_and(&mut self) -> EngineResult<()> {
        self.compile_equality()?;
        while matches!(self.peek(), Token::And) {
            self.advance();
            let j_false = self.code.len();
            self.code.push(OpCode::JumpIfFalse(0));
            self.compile_equality()?;
            let j_end = self.code.len();
            self.code.push(OpCode::Jump(0));
            self.code[j_false] = OpCode::JumpIfFalse(self.code.len());
            self.code.push(OpCode::PushBool(false));
            self.code[j_end] = OpCode::Jump(self.code.len());
        }
        Ok(())
    }

    fn compile_equality(&mut self) -> EngineResult<()> {
        self.compile_comparison()?;
        loop {
            match self.peek() {
                Token::EqEq => {
                    self.advance();
                    self.compile_comparison()?;
                    self.code.push(OpCode::Eq);
                }
                Token::NotEq => {
                    self.advance();
                    self.compile_comparison()?;
                    self.code.push(OpCode::Ne);
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn compile_comparison(&mut self) -> EngineResult<()> {
        self.compile_term()?;
        loop {
            match self.peek() {
                Token::Lt => {
                    self.advance();
                    self.compile_term()?;
                    self.code.push(OpCode::Lt);
                }
                Token::Le => {
                    self.advance();
                    self.compile_term()?;
                    self.code.push(OpCode::Le);
                }
                Token::Gt => {
                    self.advance();
                    self.compile_term()?;
                    self.code.push(OpCode::Gt);
                }
                Token::Ge => {
                    self.advance();
                    self.compile_term()?;
                    self.code.push(OpCode::Ge);
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn compile_term(&mut self) -> EngineResult<()> {
        self.compile_factor()?;
        loop {
            match self.peek() {
                Token::Plus | Token::Concat => {
                    self.advance();
                    self.compile_factor()?;
                    self.code.push(OpCode::Add);
                }
                Token::Minus => {
                    self.advance();
                    self.compile_factor()?;
                    self.code.push(OpCode::Sub);
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn compile_factor(&mut self) -> EngineResult<()> {
        self.compile_unary()?;
        loop {
            match self.peek() {
                Token::Star => {
                    self.advance();
                    self.compile_unary()?;
                    self.code.push(OpCode::Mul);
                }
                Token::Slash => {
                    self.advance();
                    self.compile_unary()?;
                    self.code.push(OpCode::Div);
                }
                Token::Percent => {
                    self.advance();
                    self.compile_unary()?;
                    self.code.push(OpCode::Mod);
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn compile_unary(&mut self) -> EngineResult<()> {
        match self.peek() {
            Token::Minus => {
                self.advance();
                self.compile_unary()?;
                self.code.push(OpCode::Neg);
                Ok(())
            }
            Token::Bang => {
                self.advance();
                self.compile_unary()?;
                self.code.push(OpCode::Not);
                Ok(())
            }
            _ => self.compile_primary(),
        }
    }

    fn compile_primary(&mut self) -> EngineResult<()> {
        match self.advance() {
            Token::Int(n) => {
                self.code.push(OpCode::PushInt(n));
                Ok(())
            }
            Token::Str(s) => {
                self.code.push(OpCode::PushStr(s.into_boxed_slice()));
                Ok(())
            }
            Token::LParen => {
                self.compile_expr()?;
                self.expect_token(&Token::RParen)
            }
            Token::Ident(name) => {
                if name == "true" {
                    self.code.push(OpCode::PushBool(true));
                    return Ok(());
                }
                if name == "false" {
                    self.code.push(OpCode::PushBool(false));
                    return Ok(());
                }
                if name == "nil" || name == "null" {
                    self.code.push(OpCode::PushNull);
                    return Ok(());
                }
                if name == "KEYS" {
                    self.expect_token(&Token::LBracket)?;
                    self.compile_expr()?;
                    self.expect_token(&Token::RBracket)?;
                    self.code.push(OpCode::LoadKey);
                    return Ok(());
                }
                if name == "ARGV" {
                    self.expect_token(&Token::LBracket)?;
                    self.compile_expr()?;
                    self.expect_token(&Token::RBracket)?;
                    self.code.push(OpCode::LoadArg);
                    return Ok(());
                }
                if name == "redis" && matches!(self.peek(), Token::Dot) {
                    self.advance();
                    let sub = self.advance();
                    if sub != Token::Ident("call".to_string())
                        && sub != Token::Ident("pcall".to_string())
                    {
                        return Err(EngineError::InvalidArgument(
                            "VM only supports redis.call / redis.pcall".to_string(),
                        ));
                    }
                    return self.compile_host_call();
                }
                if name == "call" {
                    return self.compile_host_call();
                }
                if name == "tonumber" {
                    self.expect_token(&Token::LParen)?;
                    self.compile_expr()?;
                    self.expect_token(&Token::RParen)?;
                    self.code.push(OpCode::ToNumber);
                    return Ok(());
                }
                if name == "tostring" {
                    self.expect_token(&Token::LParen)?;
                    self.compile_expr()?;
                    self.expect_token(&Token::RParen)?;
                    self.code.push(OpCode::ToString);
                    return Ok(());
                }

                let slot = self.resolve_or_declare_local(&name);
                self.code.push(OpCode::LoadLocal(slot));
                Ok(())
            }
            other => Err(EngineError::InvalidArgument(format!(
                "VM syntax error: unexpected token {:?}",
                other
            ))),
        }
    }

    fn compile_host_call(&mut self) -> EngineResult<()> {
        self.expect_token(&Token::LParen)?;
        let mut argc = 0usize;
        if !matches!(self.peek(), Token::RParen) {
            loop {
                self.compile_expr()?;
                argc += 1;
                if matches!(self.peek(), Token::Comma) {
                    self.advance();
                } else {
                    break;
                }
            }
        }
        self.expect_token(&Token::RParen)?;
        if argc == 0 {
            return Err(EngineError::InvalidArgument(
                "call() requires at least a command name".to_string(),
            ));
        }
        self.code.push(OpCode::HostCall(argc));
        Ok(())
    }
}

pub fn compile_script(source: &[u8]) -> EngineResult<CompiledScript> {
    let tokens = lex_script(source)?;
    let mut compiler = Compiler::new(tokens);
    compiler.compile_program()?;
    Ok(CompiledScript {
        code: compiler.code,
        num_locals: compiler.locals.len(),
    })
}

/// Deterministic stack-based bytecode virtual machine with instruction-fuel sandboxing.
pub struct FerrumVm {
    max_steps: usize,
}

impl Default for FerrumVm {
    fn default() -> Self {
        Self::new(DEFAULT_VM_MAX_STEPS)
    }
}

impl FerrumVm {
    pub fn new(max_steps: usize) -> Self {
        Self { max_steps }
    }

    pub fn execute(
        &self,
        script: &CompiledScript,
        keys: &[&[u8]],
        argv: &[&[u8]],
        storage: &StorageEngine,
    ) -> EngineResult<VmValue> {
        let mut stack: Vec<VmValue> = Vec::with_capacity(32);
        let mut locals: Vec<VmValue> = vec![VmValue::Null; script.num_locals];
        let mut pc = 0usize;
        let mut steps = 0usize;

        while pc < script.code.len() {
            if steps >= self.max_steps {
                return Err(EngineError::InvalidArgument(format!(
                    "script exceeded maximum instruction fuel ({} steps)",
                    self.max_steps
                )));
            }
            steps += 1;

            match &script.code[pc] {
                OpCode::PushNull => {
                    stack.push(VmValue::Null);
                    pc += 1;
                }
                OpCode::PushBool(b) => {
                    stack.push(VmValue::Bool(*b));
                    pc += 1;
                }
                OpCode::PushInt(n) => {
                    stack.push(VmValue::Int(*n));
                    pc += 1;
                }
                OpCode::PushStr(s) => {
                    stack.push(VmValue::Str(s.to_vec()));
                    pc += 1;
                }
                OpCode::LoadLocal(slot) => {
                    stack.push(locals[*slot].clone());
                    pc += 1;
                }
                OpCode::StoreLocal(slot) => {
                    let v = pop_val(&mut stack)?;
                    locals[*slot] = v;
                    pc += 1;
                }
                OpCode::LoadKey => {
                    let idx_val = pop_val(&mut stack)?.as_int()?;
                    let resolved = resolve_1_or_0_index(idx_val, keys.len());
                    match resolved.and_then(|i| keys.get(i)) {
                        Some(&k) => stack.push(VmValue::Str(k.to_vec())),
                        None => stack.push(VmValue::Null),
                    }
                    pc += 1;
                }
                OpCode::LoadArg => {
                    let idx_val = pop_val(&mut stack)?.as_int()?;
                    let resolved = resolve_1_or_0_index(idx_val, argv.len());
                    match resolved.and_then(|i| argv.get(i)) {
                        Some(&a) => stack.push(VmValue::Str(a.to_vec())),
                        None => stack.push(VmValue::Null),
                    }
                    pc += 1;
                }
                OpCode::Add => {
                    let rhs = pop_val(&mut stack)?;
                    let lhs = pop_val(&mut stack)?;
                    match (&lhs, &rhs) {
                        (VmValue::Str(a), VmValue::Str(b)) => {
                            let mut c = Vec::with_capacity(a.len() + b.len());
                            c.extend_from_slice(a);
                            c.extend_from_slice(b);
                            stack.push(VmValue::Str(c));
                        }
                        _ => {
                            let res = lhs.as_int()?.checked_add(rhs.as_int()?).ok_or_else(|| {
                                EngineError::InvalidArgument("VM integer overflow".to_string())
                            })?;
                            stack.push(VmValue::Int(res));
                        }
                    }
                    pc += 1;
                }
                OpCode::Sub => {
                    let r = pop_val(&mut stack)?.as_int()?;
                    let l = pop_val(&mut stack)?.as_int()?;
                    stack.push(VmValue::Int(l.wrapping_sub(r)));
                    pc += 1;
                }
                OpCode::Mul => {
                    let r = pop_val(&mut stack)?.as_int()?;
                    let l = pop_val(&mut stack)?.as_int()?;
                    stack.push(VmValue::Int(l.wrapping_mul(r)));
                    pc += 1;
                }
                OpCode::Div => {
                    let r = pop_val(&mut stack)?.as_int()?;
                    if r == 0 {
                        return Err(EngineError::InvalidArgument(
                            "VM division by zero".to_string(),
                        ));
                    }
                    let l = pop_val(&mut stack)?.as_int()?;
                    stack.push(VmValue::Int(l.wrapping_div(r)));
                    pc += 1;
                }
                OpCode::Mod => {
                    let r = pop_val(&mut stack)?.as_int()?;
                    if r == 0 {
                        return Err(EngineError::InvalidArgument(
                            "VM modulo by zero".to_string(),
                        ));
                    }
                    let l = pop_val(&mut stack)?.as_int()?;
                    stack.push(VmValue::Int(l.wrapping_rem(r)));
                    pc += 1;
                }
                OpCode::Neg => {
                    let v = pop_val(&mut stack)?.as_int()?;
                    stack.push(VmValue::Int(v.wrapping_neg()));
                    pc += 1;
                }
                OpCode::Not => {
                    let v = pop_val(&mut stack)?;
                    stack.push(VmValue::Bool(!v.is_truthy()));
                    pc += 1;
                }
                OpCode::Eq => {
                    let r = pop_val(&mut stack)?;
                    let l = pop_val(&mut stack)?;
                    stack.push(VmValue::Bool(values_equal(&l, &r)));
                    pc += 1;
                }
                OpCode::Ne => {
                    let r = pop_val(&mut stack)?;
                    let l = pop_val(&mut stack)?;
                    stack.push(VmValue::Bool(!values_equal(&l, &r)));
                    pc += 1;
                }
                OpCode::Lt => {
                    let r = pop_val(&mut stack)?.as_int()?;
                    let l = pop_val(&mut stack)?.as_int()?;
                    stack.push(VmValue::Bool(l < r));
                    pc += 1;
                }
                OpCode::Le => {
                    let r = pop_val(&mut stack)?.as_int()?;
                    let l = pop_val(&mut stack)?.as_int()?;
                    stack.push(VmValue::Bool(l <= r));
                    pc += 1;
                }
                OpCode::Gt => {
                    let r = pop_val(&mut stack)?.as_int()?;
                    let l = pop_val(&mut stack)?.as_int()?;
                    stack.push(VmValue::Bool(l > r));
                    pc += 1;
                }
                OpCode::Ge => {
                    let r = pop_val(&mut stack)?.as_int()?;
                    let l = pop_val(&mut stack)?.as_int()?;
                    stack.push(VmValue::Bool(l >= r));
                    pc += 1;
                }
                OpCode::ToNumber => {
                    let v = pop_val(&mut stack)?;
                    let n = match v {
                        VmValue::Int(i) => i,
                        VmValue::Str(s) => parse_i64_bytes(&s).unwrap_or(0),
                        VmValue::Bool(b) => i64::from(b),
                        _ => 0,
                    };
                    stack.push(VmValue::Int(n));
                    pc += 1;
                }
                OpCode::ToString => {
                    let v = pop_val(&mut stack)?;
                    stack.push(VmValue::Str(v.to_arg_bytes()));
                    pc += 1;
                }
                OpCode::HostCall(argc) => {
                    if stack.len() < *argc {
                        return Err(EngineError::InvalidArgument("VM stack underflow".to_string()));
                    }
                    let start = stack.len() - *argc;
                    let raw_args: Vec<Vec<u8>> = stack
                        .drain(start..)
                        .map(|v| v.to_arg_bytes())
                        .collect();
                    let result = dispatch_vm_host_call(&raw_args, storage)?;
                    stack.push(result);
                    pc += 1;
                }
                OpCode::Jump(target) => {
                    pc = *target;
                }
                OpCode::JumpIfFalse(target) => {
                    let cond = pop_val(&mut stack)?;
                    if !cond.is_truthy() {
                        pc = *target;
                    } else {
                        pc += 1;
                    }
                }
                OpCode::Pop => {
                    let _ = pop_val(&mut stack)?;
                    pc += 1;
                }
                OpCode::Return => {
                    return pop_val(&mut stack);
                }
            }
        }

        Ok(VmValue::Null)
    }
}

#[inline]
fn resolve_1_or_0_index(raw: i64, len: usize) -> Option<usize> {
    if raw >= 1 && (raw as usize) <= len {
        Some((raw as usize) - 1)
    } else if raw == 0 && len > 0 {
        Some(0)
    } else {
        None
    }
}

#[inline]
fn pop_val(stack: &mut Vec<VmValue>) -> EngineResult<VmValue> {
    stack
        .pop()
        .ok_or_else(|| EngineError::InvalidArgument("VM stack underflow".to_string()))
}

fn values_equal(a: &VmValue, b: &VmValue) -> bool {
    match (a, b) {
        (VmValue::Null, VmValue::Null) => true,
        (VmValue::Bool(x), VmValue::Bool(y)) => x == y,
        (VmValue::Int(x), VmValue::Int(y)) => x == y,
        (VmValue::Str(x), VmValue::Str(y)) => x == y,
        (VmValue::Int(x), VmValue::Str(y)) | (VmValue::Str(y), VmValue::Int(x)) => {
            parse_i64_bytes(y).map(|n| n == *x).unwrap_or(false)
        }
        _ => false,
    }
}

fn dispatch_vm_host_call(raw_args: &[Vec<u8>], storage: &StorageEngine) -> EngineResult<VmValue> {
    let slices: Vec<&[u8]> = raw_args.iter().map(|v| v.as_slice()).collect();
    let cmd = slices[0];

    if cmd.eq_ignore_ascii_case(b"GET") && slices.len() == 2 {
        return Ok(match storage.get_bytes(slices[1])? {
            Some(b) => VmValue::Str(b.into_vec()),
            None => VmValue::Null,
        });
    }
    if cmd.eq_ignore_ascii_case(b"SET") && slices.len() >= 3 {
        let mut cond = SetCondition::Always;
        let mut ttl = None;
        let mut i = 3usize;
        while i < slices.len() {
            if slices[i].eq_ignore_ascii_case(b"NX") {
                cond = SetCondition::IfAbsent;
                i += 1;
            } else if slices[i].eq_ignore_ascii_case(b"XX") {
                cond = SetCondition::IfPresent;
                i += 1;
            } else if slices[i].eq_ignore_ascii_case(b"PX") && i + 1 < slices.len() {
                let ms = parse_i64_bytes(slices[i + 1])?;
                ttl = Some(Duration::from_millis(ms.max(1) as u64));
                i += 2;
            } else if slices[i].eq_ignore_ascii_case(b"EX") && i + 1 < slices.len() {
                let s = parse_i64_bytes(slices[i + 1])?;
                ttl = Some(Duration::from_secs(s.max(1) as u64));
                i += 2;
            } else {
                break;
            }
        }
        let ok = storage.set(slices[1], slices[2], ttl, cond)?;
        return Ok(if ok {
            VmValue::Str(b"OK".to_vec())
        } else {
            VmValue::Null
        });
    }
    if cmd.eq_ignore_ascii_case(b"DEL") && slices.len() >= 2 {
        return Ok(VmValue::Int(storage.del(&slices[1..])? as i64));
    }
    if cmd.eq_ignore_ascii_case(b"EXISTS") && slices.len() >= 2 {
        return Ok(VmValue::Int(storage.exists(&slices[1..])? as i64));
    }
    if cmd.eq_ignore_ascii_case(b"INCR") && slices.len() == 2 {
        return Ok(VmValue::Int(storage.incr_by(slices[1], 1)?));
    }
    if cmd.eq_ignore_ascii_case(b"DECR") && slices.len() == 2 {
        return Ok(VmValue::Int(storage.incr_by(slices[1], -1)?));
    }
    if cmd.eq_ignore_ascii_case(b"INCRBY") && slices.len() == 3 {
        let d = parse_i64_bytes(slices[2])?;
        return Ok(VmValue::Int(storage.incr_by(slices[1], d)?));
    }
    if cmd.eq_ignore_ascii_case(b"HSET") && slices.len() >= 4 && slices.len() % 2 == 0 {
        let mut pairs = Vec::new();
        let mut i = 2;
        while i + 1 < slices.len() {
            pairs.push((slices[i], slices[i + 1]));
            i += 2;
        }
        return Ok(VmValue::Int(storage.hset(slices[1], &pairs)? as i64));
    }
    if cmd.eq_ignore_ascii_case(b"ZADD") && slices.len() >= 4 && slices.len() % 2 == 0 {
        let mut entries = Vec::new();
        let mut i = 2;
        while i + 1 < slices.len() {
            entries.push((parse_f64_bytes(slices[i])?, slices[i + 1]));
            i += 2;
        }
        return Ok(VmValue::Int(storage.zadd(slices[1], &entries)? as i64));
    }
    if cmd.eq_ignore_ascii_case(b"LPUSH") && slices.len() >= 3 {
        return Ok(VmValue::Int(storage.list_push(slices[1], &slices[2..], true)? as i64));
    }
    if cmd.eq_ignore_ascii_case(b"RPUSH") && slices.len() >= 3 {
        return Ok(VmValue::Int(storage.list_push(slices[1], &slices[2..], false)? as i64));
    }

    Err(EngineError::InvalidArgument(format!(
        "VM unsupported host command '{}'",
        String::from_utf8_lossy(cmd)
    )))
}

/// Thread-safe SHA-256 keyed bytecode cache (`SCRIPT LOAD`, `SCRIPT EXISTS`, `EVALSHA`).
pub struct ScriptCache {
    scripts: RwLock<RawHashTable<Arc<CompiledScript>>>,
    vm: FerrumVm,
}

impl Default for ScriptCache {
    fn default() -> Self {
        Self::new(DEFAULT_VM_MAX_STEPS)
    }
}

impl ScriptCache {
    pub fn new(max_steps: usize) -> Self {
        Self {
            scripts: RwLock::new(RawHashTable::new()),
            vm: FerrumVm::new(max_steps),
        }
    }

    pub fn load_script(&self, src: &[u8]) -> EngineResult<(String, Arc<CompiledScript>)> {
        let digest = sha256_hex(src);
        let digest_lower = digest.to_ascii_lowercase();
        {
            let rguard = self
                .scripts
                .read()
                .map_err(|_| EngineError::LockPoisoned("script cache read"))?;
            if let Some(existing) = rguard.get(digest_lower.as_bytes()) {
                return Ok((digest_lower, Arc::clone(existing)));
            }
        }
        let compiled = Arc::new(compile_script(src)?);
        let mut wguard = self
            .scripts
            .write()
            .map_err(|_| EngineError::LockPoisoned("script cache write"))?;
        wguard.insert(
            digest_lower.as_bytes().to_vec().into_boxed_slice(),
            Arc::clone(&compiled),
        );
        Ok((digest_lower, compiled))
    }

    pub fn exists(&self, digests: &[&[u8]]) -> EngineResult<Vec<bool>> {
        let guard = self
            .scripts
            .read()
            .map_err(|_| EngineError::LockPoisoned("script cache read"))?;
        let mut out = Vec::with_capacity(digests.len());
        for &d in digests {
            let norm = String::from_utf8_lossy(d).to_ascii_lowercase();
            out.push(guard.contains_key(norm.as_bytes()));
        }
        Ok(out)
    }

    pub fn flush(&self) -> EngineResult<()> {
        let mut guard = self
            .scripts
            .write()
            .map_err(|_| EngineError::LockPoisoned("script cache write"))?;
        guard.clear();
        Ok(())
    }

    pub fn eval_source(
        &self,
        src: &[u8],
        keys: &[&[u8]],
        argv: &[&[u8]],
        storage: &StorageEngine,
    ) -> EngineResult<VmValue> {
        let (_, compiled) = self.load_script(src)?;
        self.vm.execute(&compiled, keys, argv, storage)
    }

    pub fn eval_sha(
        &self,
        sha_hex: &[u8],
        keys: &[&[u8]],
        argv: &[&[u8]],
        storage: &StorageEngine,
    ) -> EngineResult<VmValue> {
        let norm = String::from_utf8_lossy(sha_hex).to_ascii_lowercase();
        let compiled = {
            let guard = self
                .scripts
                .read()
                .map_err(|_| EngineError::LockPoisoned("script cache read"))?;
            guard
                .get(norm.as_bytes())
                .cloned()
                .ok_or_else(|| {
                    EngineError::InvalidArgument(
                        "NOSCRIPT No matching script. Please use EVAL.".to_string(),
                    )
                })?
        };
        self.vm.execute(&compiled, keys, argv, storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_180_4_sha256_vectors_and_vm_fuel_sandbox() -> EngineResult<()> {
        // NIST FIPS 180-4 official SHA-256 test vectors
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );

        let storage = StorageEngine::new(8)?;
        let cache = ScriptCache::new(100_000);

        // Atomic Compare-And-Swap + loop script
        let cas_script = br#"
            let cur = call("GET", KEYS[1]);
            if cur == nil || cur == ARGV[1] {
                call("SET", KEYS[1], ARGV[2]);
                let acc = 0;
                let i = 1;
                while i <= 5 {
                    acc = acc + i;
                    i = i + 1;
                }
                return acc;
            } else {
                return 0;
            }
        "#;

        let (sha, _) = cache.load_script(cas_script)?;
        assert_eq!(cache.exists(&[sha.as_bytes()])?, vec![true]);

        let res1 = cache.eval_sha(sha.as_bytes(), &[b"acct:1"], &[b"0", b"100"], &storage)?;
        assert_eq!(res1, VmValue::Int(15));
        assert_eq!(storage.get_bytes(b"acct:1")?.as_deref(), Some(b"100".as_slice()));

        // Mismatched expected value fails CAS
        let res2 = cache.eval_sha(sha.as_bytes(), &[b"acct:1"], &[b"999", b"200"], &storage)?;
        assert_eq!(res2, VmValue::Int(0));

        // Infinite loop must halt cleanly at instruction fuel boundary
        let inf = b"let x = 0; while true { x = x + 1; } return x;";
        let err = cache.eval_source(inf, &[], &[], &storage);
        assert!(err.is_err());
        Ok(())
    }
}
