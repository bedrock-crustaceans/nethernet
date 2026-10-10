use http::header::{
    CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, EXPECT, HOST, InvalidHeaderValue, TRANSFER_ENCODING,
    USER_AGENT,
};
use http::uri::{InvalidUri, PathAndQuery};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use nethernet::signaling::http::join;
use std::fmt::Write as _;

const MAX_HEADERS: usize = 100;
pub(crate) const MAX_BODY: usize = 1 << 20;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FramingError {
    #[error("too many headers")]
    TooManyHeaders,
    #[error("malformed message")]
    Malformed,
    #[error("message too large")]
    TooLarge,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RequestError {
    #[error("too many headers")]
    TooManyHeaders,
    #[error("malformed request")]
    Malformed,
    #[error("request too large")]
    TooLarge,
}

impl From<FramingError> for RequestError {
    fn from(error: FramingError) -> Self {
        match error {
            FramingError::TooManyHeaders => Self::TooManyHeaders,
            FramingError::Malformed => Self::Malformed,
            FramingError::TooLarge => Self::TooLarge,
        }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ResponseError {
    #[error("too many headers")]
    TooManyHeaders,
    #[error("malformed response")]
    Malformed,
    #[error("response too large")]
    TooLarge,
    #[error("response has neither a content length nor chunked encoding")]
    UnboundedBody,
}

impl From<FramingError> for ResponseError {
    fn from(error: FramingError) -> Self {
        match error {
            FramingError::TooManyHeaders => Self::TooManyHeaders,
            FramingError::Malformed => Self::Malformed,
            FramingError::TooLarge => Self::TooLarge,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("body is not valid UTF-8")]
pub(crate) struct NotUtf8(#[from] std::string::FromUtf8Error);

/// Converts the byte bodies the readers return into text, at the edge.
pub(crate) struct TextBody;

impl TextBody {
    pub(crate) fn decode(body: Vec<u8>) -> Result<String, NotUtf8> {
        Ok(String::from_utf8(body)?)
    }

    pub(crate) fn request(request: Request<Vec<u8>>) -> Result<Request<String>, NotUtf8> {
        let (parts, body) = request.into_parts();
        Ok(Request::from_parts(parts, Self::decode(body)?))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum BodyFraming {
    Length(usize),
    Chunked,
}

impl BodyFraming {
    fn of(headers: &[httparse::Header]) -> Result<Option<Self>, FramingError> {
        let length = headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()));
        let encoding = headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(TRANSFER_ENCODING.as_str()));
        match (length, encoding) {
            (Some(_), Some(_)) => Err(FramingError::Malformed),
            (None, Some(encoding))
                if encoding.value.trim_ascii().eq_ignore_ascii_case(b"chunked") =>
            {
                Ok(Some(Self::Chunked))
            }
            (None, Some(_)) => Err(FramingError::Malformed),
            (Some(length), None) => {
                let length: usize = std::str::from_utf8(length.value)
                    .ok()
                    .and_then(|v| v.trim().parse().ok())
                    .ok_or(FramingError::Malformed)?;
                if length > MAX_BODY {
                    return Err(FramingError::TooLarge);
                }
                Ok(Some(Self::Length(length)))
            }
            (None, None) => Ok(None),
        }
    }

    fn read(&self, buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, FramingError> {
        match self {
            Self::Length(length) => {
                Ok((buf.len() >= *length).then(|| (buf[..*length].to_vec(), *length)))
            }
            Self::Chunked => Ok(match ChunkedBody::decode(buf)? {
                ChunkedBody::Complete { body, consumed } => Some((body, consumed)),
                ChunkedBody::Incomplete => None,
            }),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChunkedBody {
    Complete { body: Vec<u8>, consumed: usize },
    Incomplete,
}

impl ChunkedBody {
    pub(crate) fn decode(buf: &[u8]) -> Result<Self, FramingError> {
        let mut body = Vec::new();
        let mut at = 0;
        loop {
            let (line_len, size) = match httparse::parse_chunk_size(&buf[at..]) {
                Ok(httparse::Status::Complete(parsed)) => parsed,
                Ok(httparse::Status::Partial) => return Ok(Self::Incomplete),
                Err(_) => return Err(FramingError::Malformed),
            };
            at += line_len;
            if size == 0 {
                return Ok(match Self::trailer_len(&buf[at..])? {
                    Some(trailer_len) => Self::Complete {
                        body,
                        consumed: at + trailer_len,
                    },
                    None => Self::Incomplete,
                });
            }
            let size = usize::try_from(size).map_err(|_| FramingError::TooLarge)?;
            if size > MAX_BODY - body.len() {
                return Err(FramingError::TooLarge);
            }
            let Some(chunk_end) = at.checked_add(size + 2).filter(|&end| end <= buf.len()) else {
                return Ok(Self::Incomplete);
            };
            if &buf[chunk_end - 2..chunk_end] != b"\r\n" {
                return Err(FramingError::Malformed);
            }
            body.extend_from_slice(&buf[at..chunk_end - 2]);
            at = chunk_end;
        }
    }

    fn trailer_len(rest: &[u8]) -> Result<Option<usize>, FramingError> {
        let mut trailers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        match httparse::parse_headers(rest, &mut trailers) {
            Ok(httparse::Status::Complete((len, _))) => Ok(Some(len)),
            Ok(httparse::Status::Partial) => Ok(None),
            Err(httparse::Error::TooManyHeaders) => Err(FramingError::TooManyHeaders),
            Err(_) => Err(FramingError::Malformed),
        }
    }
}

fn expects_continue(headers: &[httparse::Header]) -> bool {
    headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case(EXPECT.as_str())
            && h.value
                .trim_ascii()
                .eq_ignore_ascii_case(WireFormat::CONTINUE_EXPECTATION.as_bytes())
    })
}

#[derive(Debug)]
pub(crate) enum Parsed<T> {
    Complete(Box<T>, usize),
    Partial { expects_continue: bool },
}

/// Parses a complete HTTP/1.x request out of the front of a buffer, once one is fully
/// buffered. `Partial` means more bytes are needed, and says whether the client is
/// waiting for a `100 Continue` before it sends the body.
pub(crate) struct RequestReader;

impl RequestReader {
    pub(crate) fn parse(buf: &[u8]) -> Result<Parsed<Request<Vec<u8>>>, RequestError> {
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

        let framing = BodyFraming::of(parsed.headers)?.unwrap_or(BodyFraming::Length(0));
        let Some((body, body_len)) = framing.read(&buf[header_len..])? else {
            return Ok(Parsed::Partial {
                expects_continue: expects_continue(parsed.headers),
            });
        };

        let mut builder = Request::builder()
            .method(parsed.method.ok_or(RequestError::Malformed)?)
            .uri(parsed.path.ok_or(RequestError::Malformed)?);
        for header in parsed.headers.iter() {
            builder = builder.header(header.name, header.value);
        }
        let request = builder.body(body).map_err(|_| RequestError::Malformed)?;

        Ok(Parsed::Complete(Box::new(request), header_len + body_len))
    }
}

/// Parses a complete HTTP/1.x response out of the front of a buffer, once one is fully
/// buffered. `Partial` means more bytes are needed.
pub(crate) struct ResponseReader;

impl ResponseReader {
    pub(crate) fn parse(buf: &[u8]) -> Result<Parsed<Response<Vec<u8>>>, ResponseError> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut parsed = httparse::Response::new(&mut headers);
        let status = parsed.parse(buf).map_err(|e| match e {
            httparse::Error::TooManyHeaders => ResponseError::TooManyHeaders,
            _ => ResponseError::Malformed,
        })?;
        let httparse::Status::Complete(header_len) = status else {
            return Ok(Parsed::Partial {
                expects_continue: false,
            });
        };

        let framing = BodyFraming::of(parsed.headers)?.ok_or(ResponseError::UnboundedBody)?;
        let Some((body, body_len)) = framing.read(&buf[header_len..])? else {
            return Ok(Parsed::Partial {
                expects_continue: false,
            });
        };

        let mut builder = Response::builder().status(parsed.code.ok_or(ResponseError::Malformed)?);
        for header in parsed.headers.iter() {
            builder = builder.header(header.name, header.value);
        }
        let response = builder.body(body).map_err(|_| ResponseError::Malformed)?;

        Ok(Parsed::Complete(Box::new(response), header_len + body_len))
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WireError {
    #[error("header value is not valid on the wire")]
    InvalidHeaderValue(#[from] InvalidHeaderValue),
    #[error("request target is not valid on the wire")]
    InvalidTarget(#[from] InvalidUri),
}

struct WireFormat;

impl WireFormat {
    const CRLF: &'static str = "\r\n";
    const VERSION: &'static str = "HTTP/1.1";
    const CONTINUE_EXPECTATION: &'static str = "100-continue";
    const KEEP_ALIVE: HeaderValue = HeaderValue::from_static("keep-alive");
    const CLOSE: HeaderValue = HeaderValue::from_static("close");

    fn status_line(status: StatusCode) -> String {
        format!(
            "{} {} {}{}",
            Self::VERSION,
            status.as_str(),
            status.canonical_reason().unwrap_or(""),
            Self::CRLF
        )
    }

    fn request_line(method: &Method, target: &PathAndQuery) -> String {
        format!("{method} {target} {}{}", Self::VERSION, Self::CRLF)
    }

    fn serialize(start_line: &str, headers: &HeaderMap, body: &str, keep_alive: bool) -> Vec<u8> {
        let mut head = String::from(start_line);
        for (name, value) in headers {
            if name == CONTENT_LENGTH || name == CONNECTION {
                continue;
            }
            Self::push_header(&mut head, name.as_str(), value.as_bytes());
        }
        Self::push_header(
            &mut head,
            CONTENT_LENGTH.as_str(),
            body.len().to_string().as_bytes(),
        );
        let connection = if keep_alive {
            Self::KEEP_ALIVE
        } else {
            Self::CLOSE
        };
        Self::push_header(&mut head, CONNECTION.as_str(), connection.as_bytes());
        head.push_str(Self::CRLF);

        let mut out = head.into_bytes();
        out.extend_from_slice(body.as_bytes());
        out
    }

    fn push_header(head: &mut String, name: &str, value: &[u8]) {
        let _ = write!(head, "{name}: ");
        head.push_str(&String::from_utf8_lossy(value));
        head.push_str(Self::CRLF);
    }
}

/// Serializes responses to HTTP/1.1 wire bytes.
pub(crate) struct ResponseWriter;

impl ResponseWriter {
    /// Serializes an `http::Response<String>`, overriding any Content-Length or
    /// Connection header with the body's actual length and the keep-alive choice.
    pub(crate) fn encode(response: &Response<String>, keep_alive: bool) -> Vec<u8> {
        WireFormat::serialize(
            &WireFormat::status_line(response.status()),
            response.headers(),
            response.body(),
            keep_alive,
        )
    }

    /// The interim `100 Continue` response that releases a client waiting to send its body.
    pub(crate) fn continue_interim() -> Vec<u8> {
        let mut out = WireFormat::status_line(StatusCode::CONTINUE).into_bytes();
        out.extend_from_slice(WireFormat::CRLF.as_bytes());
        out
    }
}

/// Serializes the requests the HTTP signaling client sends.
pub(crate) struct RequestWriter;

impl RequestWriter {
    pub(crate) fn post(
        host: &str,
        path: &str,
        content_type: &str,
        body: &str,
    ) -> Result<Vec<u8>, WireError> {
        let mut headers = Self::common_headers(host)?;
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(content_type)?);
        Self::encode(&Method::POST, path, &headers, body)
    }

    pub(crate) fn get(host: &str, path: &str) -> Result<Vec<u8>, WireError> {
        let headers = Self::common_headers(host)?;
        Self::encode(&Method::GET, path, &headers, "")
    }

    fn common_headers(host: &str) -> Result<HeaderMap, WireError> {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_str(host)?);
        headers.insert(USER_AGENT, HeaderValue::from_str(join::CLIENT_USER_AGENT)?);
        Ok(headers)
    }

    fn encode(
        method: &Method,
        path: &str,
        headers: &HeaderMap,
        body: &str,
    ) -> Result<Vec<u8>, WireError> {
        let target: PathAndQuery = path.parse()?;
        Ok(WireFormat::serialize(
            &WireFormat::request_line(method, &target),
            headers,
            body,
            false,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_request(wire: &[u8]) -> (Request<String>, usize) {
        let Ok(Parsed::Complete(request, consumed)) = RequestReader::parse(wire) else {
            panic!("the request was not parsed as complete");
        };
        (TextBody::request(*request).unwrap(), consumed)
    }

    fn parsed_response(wire: &[u8]) -> (Response<Vec<u8>>, usize) {
        let Ok(Parsed::Complete(response, consumed)) = ResponseReader::parse(wire) else {
            panic!("the response was not parsed as complete");
        };
        (*response, consumed)
    }

    fn response_headers(wire: &[u8]) -> Vec<(String, String)> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut parsed = httparse::Response::new(&mut headers);
        parsed.parse(wire).unwrap();
        parsed
            .headers
            .iter()
            .map(|h| {
                (
                    h.name.to_ascii_lowercase(),
                    String::from_utf8(h.value.to_vec()).unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn a_chunked_body_is_decoded() {
        let wire = b"POST /v1/join HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";

        let (request, consumed) = parsed_request(wire);

        assert_eq!(request.body(), "hello world");
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn a_status_request_is_a_bodiless_get_of_the_status_path() {
        let wire = RequestWriter::get("example.com:19132", join::STATUS_PATH).unwrap();

        let (request, consumed) = parsed_request(&wire);

        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.uri().path(), join::STATUS_PATH);
        assert_eq!(request.headers()[HOST], "example.com:19132");
        assert_eq!(request.headers()[USER_AGENT], join::CLIENT_USER_AGENT);
        assert!(request.body().is_empty());
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn a_post_round_trips_through_the_request_parser() {
        let wire = RequestWriter::post(
            "example.com:19132",
            "/v1/join/abc?x=1",
            "application/json",
            "{\"k\":\"v\"}",
        )
        .unwrap();

        let (request, consumed) = parsed_request(&wire);

        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri().path(), "/v1/join/abc");
        assert_eq!(request.uri().query(), Some("x=1"));
        assert_eq!(request.headers()[HOST], "example.com:19132");
        assert_eq!(request.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(request.headers()[USER_AGENT], join::CLIENT_USER_AGENT);
        assert_eq!(request.headers()[CONNECTION], "close");
        assert_eq!(request.body(), "{\"k\":\"v\"}");
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn a_response_round_trips_through_the_response_parser() {
        let response = Response::builder()
            .status(StatusCode::CREATED)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, "999")
            .body("hello".to_string())
            .unwrap();

        let wire = ResponseWriter::encode(&response, true);

        let (parsed, consumed) = parsed_response(&wire);
        assert_eq!(parsed.status(), StatusCode::CREATED);
        assert_eq!(parsed.body(), b"hello");
        assert_eq!(consumed, wire.len());
        let headers = response_headers(&wire);
        assert!(headers.contains(&("content-type".into(), "application/json".into())));
        assert_eq!(
            headers
                .iter()
                .filter(|(name, _)| name == CONTENT_LENGTH.as_str())
                .collect::<Vec<_>>(),
            [&("content-length".to_string(), "5".to_string())]
        );
    }

    #[test]
    fn a_chunked_response_is_decoded() {
        let wire = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";

        let (response, consumed) = parsed_response(wire);

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), b"hello world");
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn a_chunked_request_with_trailers_is_consumed_through_them() {
        let wire = b"POST /v1/join HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nx-sum: 1\r\nx-other: 2\r\n\r\nGET /next";

        let (request, consumed) = parsed_request(wire);

        assert_eq!(request.body(), "hello");
        assert_eq!(consumed, wire.len() - b"GET /next".len());
    }

    #[test]
    fn a_malformed_trailer_section_is_malformed() {
        let wire = b"POST /v1/join HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nno colon here\r\n\r\n";

        assert!(matches!(
            RequestReader::parse(wire),
            Err(RequestError::Malformed)
        ));
    }

    #[test]
    fn an_unterminated_trailer_section_is_partial() {
        let wire = b"POST /v1/join HTTP/1.1\r\nhost: x\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nx-sum: 1\r\n";

        assert!(matches!(
            RequestReader::parse(wire),
            Ok(Parsed::Partial { .. })
        ));
    }

    #[test]
    fn a_response_without_length_or_chunking_is_unbounded() {
        let wire = b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\nhello";

        assert_eq!(
            ResponseReader::parse(wire).unwrap_err(),
            ResponseError::UnboundedBody
        );
    }

    #[test]
    fn a_non_utf8_body_is_returned_as_bytes_and_refused_as_text() {
        let wire = b"POST /v1/join HTTP/1.1\r\nhost: x\r\ncontent-length: 2\r\n\r\n\xff\xfe";

        let Ok(Parsed::Complete(request, consumed)) = RequestReader::parse(wire) else {
            panic!("the request was not parsed as complete");
        };

        assert_eq!(request.body(), &[0xff, 0xfe]);
        assert_eq!(consumed, wire.len());
        assert!(TextBody::request(*request).is_err());
    }

    #[test]
    fn keep_alive_sets_the_connection_header_of_a_response() {
        let response = Response::new(String::new());

        let keep = response_headers(&ResponseWriter::encode(&response, true));
        let close = response_headers(&ResponseWriter::encode(&response, false));

        assert!(keep.contains(&("connection".into(), "keep-alive".into())));
        assert!(close.contains(&("connection".into(), "close".into())));
    }

    #[test]
    fn the_continue_interim_is_a_bare_status_line() {
        assert_eq!(
            ResponseWriter::continue_interim(),
            b"HTTP/1.1 100 Continue\r\n\r\n"
        );
    }

    #[test]
    fn a_header_value_with_line_breaks_is_refused() {
        assert!(matches!(
            RequestWriter::post("a\r\nx-injected: 1", "/v1/join", "text/plain", ""),
            Err(WireError::InvalidHeaderValue(_))
        ));
        assert!(matches!(
            RequestWriter::post("a", "/v1/join", "text/plain\r\nx-injected: 1", ""),
            Err(WireError::InvalidHeaderValue(_))
        ));
        assert!(matches!(
            RequestWriter::get("a\nb", "/v1/join"),
            Err(WireError::InvalidHeaderValue(_))
        ));
    }

    #[test]
    fn a_path_with_line_breaks_is_refused() {
        assert!(matches!(
            RequestWriter::get("a", "/v1/join HTTP/1.1\r\nx-injected: 1"),
            Err(WireError::InvalidTarget(_))
        ));
    }
}
