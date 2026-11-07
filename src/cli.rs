use std::io::{self, BufRead, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::{EngineError, EngineResult};
use crate::resp::{
    encode_command_slices, OwnedFrame, ParseStatus, RespParser, StreamReadBuffer,
};

pub fn run_interactive_cli(addr: &str) -> EngineResult<()> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;

    let mut read_buf = StreamReadBuffer::with_capacity(16 * 1024);
    let mut write_buf = Vec::with_capacity(1024);

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut lines = stdin.lock().lines();

    println!("Connected to FerrumKV RESP3 server at {}", addr);
    println!("Type Redis commands (e.g. SET k v, GET k, ZADD lb 10 alice, SUBSCRIBE ch) or 'quit' to exit.");

    loop {
        write!(stdout, "{}> ", addr)?;
        stdout.flush()?;

        let Some(line_res) = lines.next() else {
            break;
        };
        let line = line_res?;
        let tokens = match tokenize_cli_line(&line) {
            Ok(t) => t,
            Err(err) => {
                println!("(parse error) {}", err);
                continue;
            }
        };
        if tokens.is_empty() {
            continue;
        }

        let refs: Vec<&[u8]> = tokens.iter().map(|v| v.as_slice()).collect();
        write_buf.clear();
        encode_command_slices(&mut write_buf, &refs);
        stream.write_all(&write_buf)?;
        stream.flush()?;

        let is_quit = refs[0].eq_ignore_ascii_case(b"QUIT") || refs[0].eq_ignore_ascii_case(b"EXIT");
        let is_sub = refs[0].eq_ignore_ascii_case(b"SUBSCRIBE")
            || refs[0].eq_ignore_ascii_case(b"PSUBSCRIBE");

        let expected_initial_frames = if is_sub && refs.len() > 1 {
            refs.len() - 1
        } else {
            1
        };

        for _ in 0..expected_initial_frames {
            let frame = read_one_frame(&mut stream, &mut read_buf)?;
            print_owned_frame(&frame, 0, &mut stdout)?;
        }

        if is_quit {
            break;
        }

        if is_sub {
            println!("Reading messages... (press Ctrl-C to exit subscriber stream)");
            stream.set_read_timeout(None)?;
            loop {
                let frame = read_one_frame(&mut stream, &mut read_buf)?;
                print_owned_frame(&frame, 0, &mut stdout)?;
                stdout.flush()?;
            }
        }
    }

    Ok(())
}

pub fn read_one_frame(stream: &mut TcpStream, read_buf: &mut StreamReadBuffer) -> EngineResult<OwnedFrame> {
    loop {
        match RespParser::parse(read_buf.readable_slice())? {
            ParseStatus::Complete { frame, consumed } => {
                let owned = OwnedFrame::from(&frame);
                read_buf.consume(consumed);
                return Ok(owned);
            }
            ParseStatus::Incomplete => {}
        }

        let dst = read_buf.writable_slice(4096);
        match stream.read(dst) {
            Ok(0) => {
                return Err(EngineError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "server closed connection",
                )))
            }
            Ok(n) => read_buf.advance_write(n),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(EngineError::Io(err)),
        }
    }
}

fn print_owned_frame(frame: &OwnedFrame, indent: usize, out: &mut dyn Write) -> io::Result<()> {
    let pad = " ".repeat(indent);
    match frame {
        OwnedFrame::SimpleString(b) => writeln!(out, "{}{}", pad, String::from_utf8_lossy(b)),
        OwnedFrame::SimpleError(b) => writeln!(out, "{}(error) {}", pad, String::from_utf8_lossy(b)),
        OwnedFrame::Integer(n) => writeln!(out, "{}(integer) {}", pad, n),
        OwnedFrame::Boolean(b) => writeln!(out, "{}(boolean) {}", pad, b),
        OwnedFrame::Double(d) => writeln!(out, "{}(double) {}", pad, d),
        OwnedFrame::Null => writeln!(out, "{}(nil)", pad),
        OwnedFrame::BulkString(b) => writeln!(out, "{}\"{}\"", pad, format_escaped_bytes(b)),
        OwnedFrame::Array(items) | OwnedFrame::Push(items) => {
            if items.is_empty() {
                return writeln!(out, "{}(empty array)", pad);
            }
            for (idx, item) in items.iter().enumerate() {
                write!(out, "{}{}) ", pad, idx + 1)?;
                print_nested_inline(item, indent + 3, out)?;
            }
            Ok(())
        }
        OwnedFrame::Map(pairs) => {
            if pairs.is_empty() {
                return writeln!(out, "{}(empty map)", pad);
            }
            for (idx, (k, v)) in pairs.iter().enumerate() {
                write!(out, "{}{}# ", pad, idx + 1)?;
                print_nested_inline(k, indent + 3, out)?;
                write!(out, "{}   => ", pad)?;
                print_nested_inline(v, indent + 6, out)?;
            }
            Ok(())
        }
    }
}

fn print_nested_inline(frame: &OwnedFrame, next_indent: usize, out: &mut dyn Write) -> io::Result<()> {
    match frame {
        OwnedFrame::Array(_) | OwnedFrame::Push(_) | OwnedFrame::Map(_) => {
            writeln!(out)?;
            print_owned_frame(frame, next_indent, out)
        }
        _ => print_owned_frame(frame, 0, out),
    }
}

fn format_escaped_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\\' => s.push_str("\\\\"),
            b'"' => s.push_str("\\\""),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            0x20..=0x7e => s.push(b as char),
            other => s.push_str(&format!("\\x{:02x}", other)),
        }
    }
    s
}

/// Shell-like argument tokenizer supporting single quotes, double quotes, and `\xHH` escapes.
pub fn tokenize_cli_line(line: &str) -> EngineResult<Vec<Vec<u8>>> {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    let mut args = Vec::new();

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let mut token = Vec::new();
        let mut in_single = false;
        let mut in_double = false;

        while i < bytes.len() {
            let c = bytes[i];
            if in_single {
                if c == b'\'' {
                    in_single = false;
                } else {
                    token.push(c);
                }
                i += 1;
            } else if in_double {
                if c == b'"' {
                    in_double = false;
                    i += 1;
                } else if c == b'\\' {
                    i += 1;
                    if i >= bytes.len() {
                        return Err(EngineError::InvalidArgument(
                            "unterminated escape sequence".to_string(),
                        ));
                    }
                    match bytes[i] {
                        b'n' => token.push(b'\n'),
                        b'r' => token.push(b'\r'),
                        b't' => token.push(b'\t'),
                        b'\\' => token.push(b'\\'),
                        b'"' => token.push(b'"'),
                        b'x' if i + 2 < bytes.len() => {
                            let hi = hex_nibble(bytes[i + 1])?;
                            let lo = hex_nibble(bytes[i + 2])?;
                            token.push((hi << 4) | lo);
                            i += 2;
                        }
                        other => token.push(other),
                    }
                    i += 1;
                } else {
                    token.push(c);
                    i += 1;
                }
            } else if c.is_ascii_whitespace() {
                break;
            } else if c == b'\'' {
                in_single = true;
                i += 1;
            } else if c == b'"' {
                in_double = true;
                i += 1;
            } else {
                token.push(c);
                i += 1;
            }
        }

        if in_single || in_double {
            return Err(EngineError::InvalidArgument(
                "unbalanced quotes in CLI input".to_string(),
            ));
        }
        args.push(token);
    }

    Ok(args)
}

fn hex_nibble(b: u8) -> EngineResult<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(EngineError::InvalidArgument(
            "invalid hex escape in string".to_string(),
        )),
    }
}
