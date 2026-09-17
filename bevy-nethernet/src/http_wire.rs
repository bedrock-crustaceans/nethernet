use http::{Request, Response};
use nethernet::signaling::http::join;

const MAX_HEADERS: usize = 32;
pub(crate) const MAX_BODY: usize = 1 << 20;

fn content_length(headers: &[httparse::Header]) -> Result<usize, ()> {
    let Some(header) = headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
    else {
        return Ok(0);
    };
    std::str::from_utf8(header.value)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|&n| n <= MAX_BODY)
        .ok_or(())
}

/// Parses a complete HTTP/1.x request out of the front of `buf`, once one is fully
/// buffered. `Ok(None)` means more bytes are needed.
pub(crate) fn parse_request(buf: &[u8]) -> Result<Option<(Request<String>, usize)>, ()> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers);
    let httparse::Status::Complete(header_len) = parsed.parse(buf).map_err(|_| ())? else {
        return Ok(None);
    };

    let body_len = content_length(parsed.headers)?;
    let total = header_len + body_len;
    if buf.len() < total {
        return Ok(None);
    }

    let mut builder = Request::builder()
        .method(parsed.method.ok_or(())?)
        .uri(parsed.path.ok_or(())?);
    for header in parsed.headers.iter() {
        builder = builder.header(header.name, header.value);
    }

    let body = String::from_utf8(buf[header_len..total].to_vec()).map_err(|_| ())?;
    let request = builder.body(body).map_err(|_| ())?;

    Ok(Some((request, total)))
}

/// Parses a complete HTTP/1.x response out of the front of `buf`, once one is fully
/// buffered. `Ok(None)` means more bytes are needed.
pub(crate) fn parse_response(buf: &[u8]) -> Result<Option<(u16, String)>, ()> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(header_len) = parsed.parse(buf).map_err(|_| ())? else {
        return Ok(None);
    };

    let body_len = content_length(parsed.headers)?;
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
