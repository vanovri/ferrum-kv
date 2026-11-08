use crate::error::{EngineError, EngineResult};

pub const MAX_NESTING_DEPTH: usize = 32;
pub const MAX_BULK_LEN: usize = 64 * 1024 * 1024;
pub const MAX_COLLECTION_LEN: usize = 1_048_576;

/// Zero-copy RESP3 protocol frame borrowing payload slices directly from the raw TCP read buffer.
#[derive(Debug, Clone, PartialEq)]
pub enum RespFrame<'a> {
    SimpleString(&'a [u8]),
    SimpleError(&'a [u8]),
    Integer(i64),
    BulkString(&'a [u8]),
    Null,
    Boolean(bool),
    Double(f64),
    Array(Vec<RespFrame<'a>>),
    Map(Vec<(RespFrame<'a>, RespFrame<'a>)>),
    Push(Vec<RespFrame<'a>>),
}

impl<'a> RespFrame<'a> {
    #[inline]
    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        match self {
            RespFrame::BulkString(b) | RespFrame::SimpleString(b) => Some(b),
            _ => None,
        }
    }

    pub fn serialize(&self, out: &mut Vec<u8>) {
        match self {
            RespFrame::SimpleString(bytes) => write_simple_string(out, bytes),
            RespFrame::SimpleError(bytes) => write_simple_error(out, bytes),
            RespFrame::Integer(val) => write_integer(out, *val),
            RespFrame::BulkString(bytes) => write_bulk_string(out, bytes),
            RespFrame::Null => write_null(out),
            RespFrame::Boolean(val) => write_boolean(out, *val),
            RespFrame::Double(val) => write_double(out, *val),
            RespFrame::Array(items) => {
                write_array_header(out, items.len());
                for item in items {
                    item.serialize(out);
                }
            }
            RespFrame::Map(pairs) => {
                write_map_header(out, pairs.len());
                for (k, v) in pairs {
                    k.serialize(out);
                    v.serialize(out);
                }
            }
            RespFrame::Push(items) => {
                write_push_header(out, items.len());
                for item in items {
                    item.serialize(out);
                }
            }
        }
    }
}

/// Owned RESP3 frame used for CLI decoding and out-of-buffer protocol handling.
#[derive(Debug, Clone, PartialEq)]
pub enum OwnedFrame {
    SimpleString(Vec<u8>),
    SimpleError(Vec<u8>),
    Integer(i64),
    BulkString(Vec<u8>),
    Null,
    Boolean(bool),
    Double(f64),
    Array(Vec<OwnedFrame>),
    Map(Vec<(OwnedFrame, OwnedFrame)>),
    Push(Vec<OwnedFrame>),
}

impl<'a> From<&RespFrame<'a>> for OwnedFrame {
    fn from(frame: &RespFrame<'a>) -> Self {
        match frame {
            RespFrame::SimpleString(b) => OwnedFrame::SimpleString(b.to_vec()),
            RespFrame::SimpleError(b) => OwnedFrame::SimpleError(b.to_vec()),
            RespFrame::Integer(v) => OwnedFrame::Integer(*v),
            RespFrame::BulkString(b) => OwnedFrame::BulkString(b.to_vec()),
            RespFrame::Null => OwnedFrame::Null,
            RespFrame::Boolean(v) => OwnedFrame::Boolean(*v),
            RespFrame::Double(v) => OwnedFrame::Double(*v),
            RespFrame::Array(items) => OwnedFrame::Array(items.iter().map(OwnedFrame::from).collect()),
            RespFrame::Map(pairs) => OwnedFrame::Map(
                pairs
                    .iter()
                    .map(|(k, v)| (OwnedFrame::from(k), OwnedFrame::from(v)))
                    .collect(),
            ),
            RespFrame::Push(items) => OwnedFrame::Push(items.iter().map(OwnedFrame::from).collect()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ParseStatus<'a> {
    Complete {
        frame: RespFrame<'a>,
        consumed: usize,
    },
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlatParseStatus {
    Complete { consumed: usize },
    Incomplete,
    Fallback,
}

pub trait FlatArgSink<'a> {
    fn clear_args(&mut self);
    fn reserve_args(&mut self, count: usize);
    fn push_arg(&mut self, buf: &'a [u8], start: usize, end: usize);
}

impl<'a> FlatArgSink<'a> for Vec<&'a [u8]> {
    #[inline]
    fn clear_args(&mut self) {
        self.clear();
    }

    #[inline]
    fn reserve_args(&mut self, count: usize) {
        if self.capacity() < count {
            self.reserve(count - self.len());
        }
    }

    #[inline]
    fn push_arg(&mut self, buf: &'a [u8], start: usize, end: usize) {
        self.push(&buf[start..end]);
    }
}

impl<'a> FlatArgSink<'a> for Vec<(usize, usize)> {
    #[inline]
    fn clear_args(&mut self) {
        self.clear();
    }

    #[inline]
    fn reserve_args(&mut self, count: usize) {
        if self.capacity() < count {
            self.reserve(count - self.len());
        }
    }

    #[inline]
    fn push_arg(&mut self, _buf: &'a [u8], start: usize, end: usize) {
        self.push((start, end));
    }
}

#[derive(Debug, Clone, Copy)]
enum LineKind {
    SimpleString,
    SimpleError,
    Integer,
    BulkLength,
    ArrayLength,
    MapLength,
    PushLength,
    Null,
    Boolean,
    Double,
}

enum ContainerState<'a> {
    Array {
        remaining: usize,
        items: Vec<RespFrame<'a>>,
    },
    Push {
        remaining: usize,
        items: Vec<RespFrame<'a>>,
    },
    Map {
        remaining_pairs: usize,
        pending_key: Option<RespFrame<'a>>,
        pairs: Vec<(RespFrame<'a>, RespFrame<'a>)>,
    },
}

enum MachineState<'a> {
    InspectType,
    ScanLine { kind: LineKind, start: usize },
    ReadBulkPayload { start: usize, len: usize },
    ScanInline { start: usize },
    Emit(RespFrame<'a>),
}

/// Iterative, non-recursive deterministic finite state machine RESP3 byte-slice parser.
pub struct RespParser;

impl RespParser {
    /// Zero-allocation fast-path parser for flat 1D RESP Arrays of BulkStrings (`*N\r\n$L\r\n...\r\n`).
    pub fn parse_flat_command<'a, S: FlatArgSink<'a>>(
        buf: &'a [u8],
        scratch_args: &mut S,
    ) -> EngineResult<FlatParseStatus> {
        scratch_args.clear_args();
        if buf.is_empty() {
            return Ok(FlatParseStatus::Incomplete);
        }
        if buf[0] != b'*' {
            return Ok(FlatParseStatus::Fallback);
        }

        let Some(hdr_end) = find_crlf(buf, 1) else {
            return Ok(FlatParseStatus::Incomplete);
        };
        let raw_count = parse_i64_bytes(&buf[1..hdr_end])?;
        if raw_count <= 0 {
            return Ok(FlatParseStatus::Fallback);
        }
        let count = raw_count as usize;
        if count > MAX_COLLECTION_LEN {
            return Err(EngineError::Protocol(
                "array length exceeds protocol limit".to_string(),
            ));
        }

        scratch_args.reserve_args(count.min(64));
        let mut cursor = hdr_end + 2;

        for _ in 0..count {
            if cursor >= buf.len() {
                scratch_args.clear_args();
                return Ok(FlatParseStatus::Incomplete);
            }
            match buf[cursor] {
                b'$' => {
                    let Some(len_end) = find_crlf(buf, cursor + 1) else {
                        scratch_args.clear_args();
                        return Ok(FlatParseStatus::Incomplete);
                    };
                    let raw_len = parse_i64_bytes(&buf[cursor + 1..len_end])?;
                    if raw_len < 0 {
                        scratch_args.clear_args();
                        return Ok(FlatParseStatus::Fallback);
                    }
                    let len = raw_len as usize;
                    if len > MAX_BULK_LEN {
                        scratch_args.clear_args();
                        return Err(EngineError::Protocol(
                            "bulk string exceeds maximum allowed frame size".to_string(),
                        ));
                    }
                    let start = len_end + 2;
                    let needed_end = start.saturating_add(len).saturating_add(2);
                    if buf.len() < needed_end {
                        scratch_args.clear_args();
                        return Ok(FlatParseStatus::Incomplete);
                    }
                    if buf[start + len] != b'\r' || buf[start + len + 1] != b'\n' {
                        scratch_args.clear_args();
                        return Err(EngineError::Protocol(
                            "bulk string missing trailing CRLF".to_string(),
                        ));
                    }
                    scratch_args.push_arg(buf, start, start + len);
                    cursor = needed_end;
                }
                b'+' => {
                    let Some(line_end) = find_crlf(buf, cursor + 1) else {
                        scratch_args.clear_args();
                        return Ok(FlatParseStatus::Incomplete);
                    };
                    let start = cursor + 1;
                    validate_no_bare_cr_lf(&buf[start..line_end])?;
                    scratch_args.push_arg(buf, start, line_end);
                    cursor = line_end + 2;
                }
                _ => {
                    scratch_args.clear_args();
                    return Ok(FlatParseStatus::Fallback);
                }
            }
        }

        Ok(FlatParseStatus::Complete { consumed: cursor })
    }

    pub fn parse<'a>(buf: &'a [u8]) -> EngineResult<ParseStatus<'a>> {
        if buf.is_empty() {
            return Ok(ParseStatus::Incomplete);
        }

        let mut cursor: usize = 0;
        let mut stack: Vec<ContainerState<'a>> = Vec::new();
        let mut state = MachineState::InspectType;

        loop {
            match state {
                MachineState::InspectType => {
                    if cursor >= buf.len() {
                        return Ok(ParseStatus::Incomplete);
                    }
                    let prefix = buf[cursor];
                    match prefix {
                        b'+' => {
                            cursor += 1;
                            state = MachineState::ScanLine {
                                kind: LineKind::SimpleString,
                                start: cursor,
                            };
                        }
                        b'-' => {
                            cursor += 1;
                            state = MachineState::ScanLine {
                                kind: LineKind::SimpleError,
                                start: cursor,
                            };
                        }
                        b':' => {
                            cursor += 1;
                            state = MachineState::ScanLine {
                                kind: LineKind::Integer,
                                start: cursor,
                            };
                        }
                        b'$' => {
                            cursor += 1;
                            state = MachineState::ScanLine {
                                kind: LineKind::BulkLength,
                                start: cursor,
                            };
                        }
                        b'*' => {
                            cursor += 1;
                            state = MachineState::ScanLine {
                                kind: LineKind::ArrayLength,
                                start: cursor,
                            };
                        }
                        b'%' => {
                            cursor += 1;
                            state = MachineState::ScanLine {
                                kind: LineKind::MapLength,
                                start: cursor,
                            };
                        }
                        b'>' => {
                            cursor += 1;
                            state = MachineState::ScanLine {
                                kind: LineKind::PushLength,
                                start: cursor,
                            };
                        }
                        b'_' => {
                            cursor += 1;
                            state = MachineState::ScanLine {
                                kind: LineKind::Null,
                                start: cursor,
                            };
                        }
                        b'#' => {
                            cursor += 1;
                            state = MachineState::ScanLine {
                                kind: LineKind::Boolean,
                                start: cursor,
                            };
                        }
                        b',' => {
                            cursor += 1;
                            state = MachineState::ScanLine {
                                kind: LineKind::Double,
                                start: cursor,
                            };
                        }
                        _ => {
                            if !stack.is_empty() {
                                return Err(EngineError::Protocol(format!(
                                    "unexpected nested RESP type prefix 0x{:02x}",
                                    prefix
                                )));
                            }
                            state = MachineState::ScanInline { start: cursor };
                        }
                    }
                }

                MachineState::ScanLine { kind, start } => {
                    let Some(line_end) = find_crlf(buf, start) else {
                        return Ok(ParseStatus::Incomplete);
                    };
                    let line = &buf[start..line_end];
                    cursor = line_end + 2;

                    match kind {
                        LineKind::SimpleString => {
                            validate_no_bare_cr_lf(line)?;
                            state = MachineState::Emit(RespFrame::SimpleString(line));
                        }
                        LineKind::SimpleError => {
                            validate_no_bare_cr_lf(line)?;
                            state = MachineState::Emit(RespFrame::SimpleError(line));
                        }
                        LineKind::Integer => {
                            let val = parse_i64_bytes(line)?;
                            state = MachineState::Emit(RespFrame::Integer(val));
                        }
                        LineKind::Null => {
                            if !line.is_empty() {
                                return Err(EngineError::Protocol(
                                    "RESP3 null frame must have empty body".to_string(),
                                ));
                            }
                            state = MachineState::Emit(RespFrame::Null);
                        }
                        LineKind::Boolean => {
                            let b = match line {
                                b"t" => true,
                                b"f" => false,
                                _ => {
                                    return Err(EngineError::Protocol(
                                        "invalid RESP3 boolean literal".to_string(),
                                    ))
                                }
                            };
                            state = MachineState::Emit(RespFrame::Boolean(b));
                        }
                        LineKind::Double => {
                            let val = parse_f64_bytes(line)?;
                            state = MachineState::Emit(RespFrame::Double(val));
                        }
                        LineKind::BulkLength => {
                            let raw_len = parse_i64_bytes(line)?;
                            if raw_len == -1 {
                                state = MachineState::Emit(RespFrame::Null);
                            } else if raw_len < -1 {
                                return Err(EngineError::Protocol(
                                    "negative bulk string length".to_string(),
                                ));
                            } else {
                                let len = raw_len as usize;
                                if len > MAX_BULK_LEN {
                                    return Err(EngineError::Protocol(
                                        "bulk string exceeds maximum allowed frame size".to_string(),
                                    ));
                                }
                                state = MachineState::ReadBulkPayload { start: cursor, len };
                            }
                        }
                        LineKind::ArrayLength => {
                            let raw_len = parse_i64_bytes(line)?;
                            if raw_len == -1 {
                                state = MachineState::Emit(RespFrame::Null);
                            } else if raw_len < -1 {
                                return Err(EngineError::Protocol(
                                    "negative array length".to_string(),
                                ));
                            } else {
                                let len = raw_len as usize;
                                if len > MAX_COLLECTION_LEN {
                                    return Err(EngineError::Protocol(
                                        "array length exceeds protocol limit".to_string(),
                                    ));
                                }
                                if len == 0 {
                                    state = MachineState::Emit(RespFrame::Array(Vec::new()));
                                } else {
                                    if stack.len() >= MAX_NESTING_DEPTH {
                                        return Err(EngineError::Protocol(
                                            "maximum RESP3 nesting depth exceeded".to_string(),
                                        ));
                                    }
                                    stack.push(ContainerState::Array {
                                        remaining: len,
                                        items: Vec::with_capacity(len.min(64)),
                                    });
                                    state = MachineState::InspectType;
                                }
                            }
                        }
                        LineKind::PushLength => {
                            let raw_len = parse_i64_bytes(line)?;
                            if raw_len < 0 {
                                return Err(EngineError::Protocol(
                                    "negative push frame length".to_string(),
                                ));
                            }
                            let len = raw_len as usize;
                            if len > MAX_COLLECTION_LEN {
                                return Err(EngineError::Protocol(
                                    "push frame length exceeds protocol limit".to_string(),
                                ));
                            }
                            if len == 0 {
                                state = MachineState::Emit(RespFrame::Push(Vec::new()));
                            } else {
                                if stack.len() >= MAX_NESTING_DEPTH {
                                    return Err(EngineError::Protocol(
                                        "maximum RESP3 nesting depth exceeded".to_string(),
                                    ));
                                }
                                stack.push(ContainerState::Push {
                                    remaining: len,
                                    items: Vec::with_capacity(len.min(64)),
                                });
                                state = MachineState::InspectType;
                            }
                        }
                        LineKind::MapLength => {
                            let raw_len = parse_i64_bytes(line)?;
                            if raw_len == -1 {
                                state = MachineState::Emit(RespFrame::Null);
                            } else if raw_len < -1 {
                                return Err(EngineError::Protocol(
                                    "negative map length".to_string(),
                                ));
                            } else {
                                let len = raw_len as usize;
                                if len > MAX_COLLECTION_LEN {
                                    return Err(EngineError::Protocol(
                                        "map length exceeds protocol limit".to_string(),
                                    ));
                                }
                                if len == 0 {
                                    state = MachineState::Emit(RespFrame::Map(Vec::new()));
                                } else {
                                    if stack.len() >= MAX_NESTING_DEPTH {
                                        return Err(EngineError::Protocol(
                                            "maximum RESP3 nesting depth exceeded".to_string(),
                                        ));
                                    }
                                    stack.push(ContainerState::Map {
                                        remaining_pairs: len,
                                        pending_key: None,
                                        pairs: Vec::with_capacity(len.min(64)),
                                    });
                                    state = MachineState::InspectType;
                                }
                            }
                        }
                    }
                }

                MachineState::ReadBulkPayload { start, len } => {
                    let needed_end = start.saturating_add(len).saturating_add(2);
                    if buf.len() < needed_end {
                        return Ok(ParseStatus::Incomplete);
                    }
                    if buf[start + len] != b'\r' || buf[start + len + 1] != b'\n' {
                        return Err(EngineError::Protocol(
                            "bulk string missing trailing CRLF".to_string(),
                        ));
                    }
                    let slice = &buf[start..start + len];
                    cursor = needed_end;
                    state = MachineState::Emit(RespFrame::BulkString(slice));
                }

                MachineState::ScanInline { start } => {
                    let Some(line_end) = find_crlf(buf, start) else {
                        return Ok(ParseStatus::Incomplete);
                    };
                    let line = &buf[start..line_end];
                    cursor = line_end + 2;
                    let mut parts = Vec::new();
                    let mut idx = 0;
                    while idx < line.len() {
                        while idx < line.len() && (line[idx] == b' ' || line[idx] == b'\t') {
                            idx += 1;
                        }
                        if idx >= line.len() {
                            break;
                        }
                        let token_start = idx;
                        while idx < line.len() && line[idx] != b' ' && line[idx] != b'\t' {
                            idx += 1;
                        }
                        parts.push(RespFrame::BulkString(&line[token_start..idx]));
                    }
                    if parts.is_empty() {
                        if cursor >= buf.len() {
                            return Ok(ParseStatus::Incomplete);
                        }
                        state = MachineState::InspectType;
                    } else {
                        state = MachineState::Emit(RespFrame::Array(parts));
                    }
                }

                MachineState::Emit(mut frame) => loop {
                    let Some(top) = stack.pop() else {
                        return Ok(ParseStatus::Complete {
                            frame,
                            consumed: cursor,
                        });
                    };

                    match top {
                        ContainerState::Array {
                            mut remaining,
                            mut items,
                        } => {
                            items.push(frame);
                            remaining -= 1;
                            if remaining == 0 {
                                frame = RespFrame::Array(items);
                                continue;
                            } else {
                                stack.push(ContainerState::Array { remaining, items });
                                state = MachineState::InspectType;
                                break;
                            }
                        }
                        ContainerState::Push {
                            mut remaining,
                            mut items,
                        } => {
                            items.push(frame);
                            remaining -= 1;
                            if remaining == 0 {
                                frame = RespFrame::Push(items);
                                continue;
                            } else {
                                stack.push(ContainerState::Push { remaining, items });
                                state = MachineState::InspectType;
                                break;
                            }
                        }
                        ContainerState::Map {
                            mut remaining_pairs,
                            mut pending_key,
                            mut pairs,
                        } => match pending_key.take() {
                            None => {
                                stack.push(ContainerState::Map {
                                    remaining_pairs,
                                    pending_key: Some(frame),
                                    pairs,
                                });
                                state = MachineState::InspectType;
                                break;
                            }
                            Some(key) => {
                                pairs.push((key, frame));
                                remaining_pairs -= 1;
                                if remaining_pairs == 0 {
                                    frame = RespFrame::Map(pairs);
                                    continue;
                                } else {
                                    stack.push(ContainerState::Map {
                                        remaining_pairs,
                                        pending_key: None,
                                        pairs,
                                    });
                                    state = MachineState::InspectType;
                                    break;
                                }
                            }
                        },
                    }
                },
            }
        }
    }
}

/// Sliding contiguous byte buffer for zero-copy streaming TCP reads.
pub struct StreamReadBuffer {
    buf: Vec<u8>,
    read_pos: usize,
    write_pos: usize,
}

impl StreamReadBuffer {
    pub fn with_capacity(cap: usize) -> Self {
        let actual = cap.max(4096);
        Self {
            buf: vec![0u8; actual],
            read_pos: 0,
            write_pos: 0,
        }
    }

    #[inline]
    pub fn readable_slice(&self) -> &[u8] {
        &self.buf[self.read_pos..self.write_pos]
    }

    #[inline]
    pub fn readable_len(&self) -> usize {
        self.write_pos - self.read_pos
    }

    #[inline]
    pub fn consume(&mut self, n: usize) {
        self.read_pos = (self.read_pos + n).min(self.write_pos);
        if self.read_pos == self.write_pos {
            self.read_pos = 0;
            self.write_pos = 0;
        }
    }

    pub fn writable_slice(&mut self, min_space: usize) -> &mut [u8] {
        if self.buf.len() - self.write_pos < min_space {
            if self.read_pos > 0 {
                let unread = self.write_pos - self.read_pos;
                self.buf.copy_within(self.read_pos..self.write_pos, 0);
                self.read_pos = 0;
                self.write_pos = unread;
            }
            if self.buf.len() - self.write_pos < min_space {
                let target = (self.write_pos + min_space).next_power_of_two();
                self.buf.resize(target, 0u8);
            }
        }
        &mut self.buf[self.write_pos..]
    }

    #[inline]
    pub fn advance_write(&mut self, n: usize) {
        self.write_pos += n;
    }

    pub fn reset(&mut self, max_retained_cap: usize) {
        self.read_pos = 0;
        self.write_pos = 0;
        if self.buf.len() > max_retained_cap {
            self.buf.truncate(max_retained_cap);
            self.buf.shrink_to_fit();
        }
    }
}

#[inline]
fn find_crlf(buf: &[u8], start: usize) -> Option<usize> {
    if buf.len() < start + 2 {
        return None;
    }
    let slice = &buf[start..];
    let mut i = 0;
    let last = slice.len() - 1;
    while i < last {
        if slice[i] == b'\r' && slice[i + 1] == b'\n' {
            return Some(start + i);
        }
        i += 1;
    }
    None
}

#[inline]
fn validate_no_bare_cr_lf(line: &[u8]) -> EngineResult<()> {
    for &b in line {
        if b == b'\r' || b == b'\n' {
            return Err(EngineError::Protocol(
                "bare CR or LF inside simple string/error".to_string(),
            ));
        }
    }
    Ok(())
}

/// Zero-allocation byte-slice signed 64-bit integer parser.
pub fn parse_i64_bytes(bytes: &[u8]) -> EngineResult<i64> {
    if bytes.is_empty() {
        return Err(EngineError::Protocol("empty integer field".to_string()));
    }
    let (neg, digits) = match bytes[0] {
        b'-' => (true, &bytes[1..]),
        b'+' => (false, &bytes[1..]),
        _ => (false, bytes),
    };
    if digits.is_empty() {
        return Err(EngineError::Protocol("missing integer digits".to_string()));
    }
    let mut acc: i128 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return Err(EngineError::InvalidArgument(
                "value is not an integer or out of range".to_string(),
            ));
        }
        acc = acc * 10 + (b - b'0') as i128;
        if !neg && acc > i64::MAX as i128 {
            return Err(EngineError::InvalidArgument(
                "value is not an integer or out of range".to_string(),
            ));
        }
        if neg && -acc < i64::MIN as i128 {
            return Err(EngineError::InvalidArgument(
                "value is not an integer or out of range".to_string(),
            ));
        }
    }
    Ok(if neg { (-acc) as i64 } else { acc as i64 })
}

pub fn parse_f64_bytes(bytes: &[u8]) -> EngineResult<f64> {
    if bytes.eq_ignore_ascii_case(b"inf") || bytes.eq_ignore_ascii_case(b"+inf") {
        return Ok(f64::INFINITY);
    }
    if bytes.eq_ignore_ascii_case(b"-inf") {
        return Ok(f64::NEG_INFINITY);
    }
    let s = std::str::from_utf8(bytes)?;
    let v: f64 = s.parse()?;
    if v.is_nan() {
        return Err(EngineError::InvalidArgument(
            "resulting score is not a number (NaN)".to_string(),
        ));
    }
    Ok(v)
}

#[inline]
pub fn write_simple_string(out: &mut Vec<u8>, msg: &[u8]) {
    out.push(b'+');
    out.extend_from_slice(msg);
    out.extend_from_slice(b"\r\n");
}

#[inline]
pub fn write_simple_error(out: &mut Vec<u8>, msg: &[u8]) {
    out.push(b'-');
    out.extend_from_slice(msg);
    out.extend_from_slice(b"\r\n");
}

#[inline]
pub fn write_integer(out: &mut Vec<u8>, val: i64) {
    out.push(b':');
    write_i64_decimal(out, val);
    out.extend_from_slice(b"\r\n");
}

#[inline]
pub fn write_bulk_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(b'$');
    write_usize_decimal(out, bytes.len());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\r\n");
}

#[inline]
pub fn write_null(out: &mut Vec<u8>) {
    out.extend_from_slice(b"_\r\n");
}

#[inline]
pub fn write_boolean(out: &mut Vec<u8>, val: bool) {
    if val {
        out.extend_from_slice(b"#t\r\n");
    } else {
        out.extend_from_slice(b"#f\r\n");
    }
}

#[inline]
pub fn write_double(out: &mut Vec<u8>, val: f64) {
    out.push(b',');
    if val == f64::INFINITY {
        out.extend_from_slice(b"inf");
    } else if val == f64::NEG_INFINITY {
        out.extend_from_slice(b"-inf");
    } else {
        let formatted = val.to_string();
        out.extend_from_slice(formatted.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
}

#[inline]
pub fn write_array_header(out: &mut Vec<u8>, len: usize) {
    out.push(b'*');
    write_usize_decimal(out, len);
    out.extend_from_slice(b"\r\n");
}

#[inline]
pub fn write_map_header(out: &mut Vec<u8>, pairs: usize) {
    out.push(b'%');
    write_usize_decimal(out, pairs);
    out.extend_from_slice(b"\r\n");
}

#[inline]
pub fn write_push_header(out: &mut Vec<u8>, len: usize) {
    out.push(b'>');
    write_usize_decimal(out, len);
    out.extend_from_slice(b"\r\n");
}

#[inline]
pub fn encode_command_slices(out: &mut Vec<u8>, parts: &[&[u8]]) {
    write_array_header(out, parts.len());
    for part in parts {
        write_bulk_string(out, part);
    }
}

#[inline]
pub fn write_i64_decimal(out: &mut Vec<u8>, val: i64) {
    if val == 0 {
        out.push(b'0');
        return;
    }
    let mut n: u64 = if val < 0 {
        out.push(b'-');
        val.wrapping_neg() as u64
    } else {
        val as u64
    };
    let mut stack = [0u8; 20];
    let mut pos = 20;
    while n > 0 {
        pos -= 1;
        stack[pos] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    out.extend_from_slice(&stack[pos..]);
}

#[inline]
pub fn write_usize_decimal(out: &mut Vec<u8>, mut val: usize) {
    if val == 0 {
        out.push(b'0');
        return;
    }
    let mut stack = [0u8; 20];
    let mut pos = 20;
    while val > 0 {
        pos -= 1;
        stack[pos] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    out.extend_from_slice(&stack[pos..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resp3_zero_copy_roundtrip_and_partial_chunks() -> EngineResult<()> {
        let original = RespFrame::Map(vec![
            (
                RespFrame::SimpleString(b"server"),
                RespFrame::BulkString(b"ferrum\r\n\x00kv"),
            ),
            (
                RespFrame::SimpleString(b"metrics"),
                RespFrame::Array(vec![
                    RespFrame::Integer(-9223372036854775808),
                    RespFrame::Boolean(true),
                    RespFrame::Double(42.5),
                    RespFrame::Null,
                    RespFrame::SimpleError(b"ERR sample"),
                ]),
            ),
        ]);

        let mut wire = Vec::new();
        original.serialize(&mut wire);

        for cut in 1..wire.len() {
            let status = RespParser::parse(&wire[..cut])?;
            assert_eq!(status, ParseStatus::Incomplete);
        }

        let full = RespParser::parse(&wire)?;
        assert_eq!(
            full,
            ParseStatus::Complete {
                frame: original,
                consumed: wire.len()
            }
        );
        Ok(())
    }
}
