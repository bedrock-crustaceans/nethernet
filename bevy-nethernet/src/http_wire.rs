use http::{Request, Response};
use nethernet::signaling::http::join;

const MAX_HEADERS: usize = 100;
pub(crate) const MAX_BODY: usize = 1 << 20;

#[derive(Debug, PartialEq, Eq)]
enum BodyFraming {
    Length(usize),
    Chunked,
}

impl BodyFraming {
    fn of(headers: &[httparse::Header]) -> Result<Self, RequestError> {
        let length = headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("content-length"));
        let encoding = headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("transfer-encoding"));
        match (length, encoding) {
            (Some(_), Some(_)) => Err(RequestError::Malformed),
            (None, Some(encoding))
                if encoding.value.trim_ascii().eq_ignore_ascii_case(b"chunked") =>
            {
                Ok(Self::Chunked)
            }
            (None, Some(_)) => Err(RequestError::Malformed),
            (Some(length), None) => {
                let length: usize = std::str::from_utf8(length.value)
                    .ok()
                    .and_then(|v| v.trim().parse().ok())
                    .ok_or(RequestError::Malformed)?;
                if length > MAX_BODY {
                    return Err(RequestError::TooLarge);
                }
                Ok(Self::Length(length))
            }
            (None, None) => Ok(Self::Length(0)),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChunkedBody {
    Complete { body: Vec<u8>, consumed: usize },
    Incomplete,
}

impl ChunkedBody {
    pub(crate) fn decode(buf: &[u8]) -> Result<Self, RequestError> {
        let mut body = Vec::new();
        let mut at = 0;
        loop {
            let (line_len, size) = match httparse::parse_chunk_size(&buf[at..]) {
                Ok(httparse::Status::Complete(parsed)) => parsed,
                Ok(httparse::Status::Partial) => return Ok(Self::Incomplete),
                Err(_) => return Err(RequestError::Malformed),
            };
            at += line_len;
            if size == 0 {
                return Ok(match Self::trailer_len(&buf[at..]) {
                    Some(trailer_len) => Self::Complete {
                        body,
                        consumed: at + trailer_len,
                    },
                    None => Self::Incomplete,
                });
            }
            let size = usize::try_from(size).map_err(|_| RequestError::TooLarge)?;
            if size > MAX_BODY - body.len() {
                return Err(RequestError::TooLarge);
            }
            let Some(chunk_end) = at.checked_add(size + 2).filter(|&end| end <= buf.len()) else {
                return Ok(Self::Incomplete);
            };
            if &buf[chunk_end - 2..chunk_end] != b"\r\n" {
                return Err(RequestError::Malformed);
            }
            body.extend_from_slice(&buf[at..chunk_end - 2]);
            at = chunk_end;
        }
    }

    fn trailer_len(rest: &[u8]) -> Option<usize> {
        if rest.starts_with(b"\r\n") {
            return Some(2);
        }
        rest.windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|at| at + 4)
    }
}

pub(crate) const CONTINUE_RESPONSE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RequestError {
    TooManyHeaders,
    Malformed,
    TooLarge,
}

fn expects_continue(headers: &[httparse::Header]) -> bool {
    headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("expect")
            && h.value.trim_ascii().eq_ignore_ascii_case(b"100-continue")
    })
}

#[derive(Debug)]
pub(crate) enum Parsed {
    Complete(Box<Request<String>>, usize),
    Partial { expects_continue: bool },
}

/// Parses a complete HTTP/1.x request out of the front of `buf`, once one is fully
/// buffered. `Partial` means more bytes are needed, and says whether the client is
/// waiting for a `100 Continue` before it sends the body.
pub(crate) fn parse_request(buf: &[u8]) -> Result<Parsed, RequestError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers);
    let status = parsed.parse(buf).map_err(|e| match e {
        httparse::Error::TooManyHeaders => RequestError::TooManyHeaders,
        _ => RequestError::Malformed,
    })?;
    let httparse::Status::Complete(header_len) = status else {
        return Ok(Parsed::Partial {
            expects_continue: false,
        });
    };

    let framing = BodyFraming::of(parsed.headers)?;
    let (body, total) = match framing {
        BodyFraming::Length(length) => {
            let total = header_len + length;
            if buf.len() < total {
                return Ok(Parsed::Partial {
                    expects_continue: expects_continue(parsed.headers),
                });
            }
            (buf[header_len..total].to_vec(), total)
        }
        BodyFraming::Chunked => match ChunkedBody::decode(&buf[header_len..])? {
            ChunkedBody::Complete { body, consumed } => (body, header_len + consumed),
            ChunkedBody::Incomplete => {
                return Ok(Parsed::Partial {
                    expects_continue: expects_continue(parsed.headers),
                });
            }
        },
    };

    let mut builder = Request::builder()
        .method(parsed.method.ok_or(RequestError::Malformed)?)
        .uri(parsed.path.ok_or(RequestError::Malformed)?);
    for header in parsed.headers.iter() {
        builder = builder.header(header.name, header.value);
    }

    let body = String::from_utf8(body).map_err(|_| RequestError::Malformed)?;
    let request = builder.body(body).map_err(|_| RequestError::Malformed)?;

    Ok(Parsed::Complete(Box::new(request), total))
}

/// Parses a complete HTTP/1.x response out of the front of `buf`, once one is fully
/// buffered. `Ok(None)` means more bytes are needed.
pub(crate) fn parse_response(buf: &[u8]) -> Result<Option<(u16, String)>, ()> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(header_len) = parsed.parse(buf).map_err(|_| ())? else {
        return Ok(None);
    };

    let BodyFraming::Length(body_len) = BodyFraming::of(parsed.headers).map_err(|_| ())? else {
        return Err(());
    };
    let total = header_len + body_len;
    if buf.len() < total {
        return Ok(None);
    }

    let code = parsed.code.ok_or(())?;
    let body = String::from_utf8(buf[header_len..total].to_vec()).map_err(|_| ())?;

    Ok(Some((code, body)))
}

/// Serializes an `http::Response<String>` to HTTP/1.1 wire bytes, overriding any
/// Content-Length header with the body's actual length.
pub(crate) fn encode_response(response: &Response<String>, keep_alive: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(response.body().len() + 128);
    let status = response.status();
    out.extend_from_slice(
        format!(
            "HTTP/1.1 {} {}\r\n",
            status.as_str(),
            status.canonical_reason().unwrap_or("")
        )
        .as_bytes(),
    );
    for (name, value) in response.headers() {
        if name.as_str().eq_ignore_ascii_case("content-length") {
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("content-length: {}\r\n", response.body().len()).as_bytes());
    out.extend_from_slice(if keep_alive {
        b"connection: keep-alive\r\n"
    } else {
        b"connection: close\r\n"
    });
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(response.body().as_bytes());
    out
}

/// Builds the wire bytes of the single POST request the HTTP signaling client sends.
pub(crate) fn encode_post(host: &str, path: &str, content_type: &str, body: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 256);
    out.extend_from_slice(format!("POST {path} HTTP/1.1\r\n").as_bytes());
    out.extend_from_slice(format!("host: {host}\r\n").as_bytes());
    out.extend_from_slice(format!("content-type: {content_type}\r\n").as_bytes());
    out.extend_from_slice(format!("user-agent: {}\r\n", join::CLIENT_USER_AGENT).as_bytes());
    out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"connection: close\r\n");
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chunked_body_is_decoded() {
        let wire = b"POST /v1/join HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";

        let Ok(Parsed::Complete(request, consumed)) = parse_request(wire) else {
            panic!("the request was not parsed as complete");
        };

        assert_eq!(request.body(), "hello world");
        assert_eq!(consumed, wire.len());
    }
}
