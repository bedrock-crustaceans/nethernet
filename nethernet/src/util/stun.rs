//! Reading just enough of a STUN message to route it, without a full ICE agent.
//!
//! A driver sharing one socket across many connections can't tell which one a datagram
//! is for by address alone until ICE settles on a remote address - before that, only
//! the STUN binding request's `USERNAME` attribute says so: RFC 5389 §15.3 (as ICE
//! uses it, RFC 8445 §7.1.3) sets it to `"{local ufrag}:{remote ufrag}"`, and the local
//! half is exactly the `ufrag` a [`crate::session::Session`] generated for itself and
//! handed back in its offer/answer [`crate::protocol::webrtc::Description`].

use rtc::stun::attributes::ATTR_USERNAME;
use rtc::stun::message::{Message, is_stun_message};
use rtc::stun::textattrs::Username;

/// The local ICE ufrag a STUN binding message names, if it is one.
///
/// Matches this against the `ufrag` handed back from [`crate::session::Session::new`]
/// for each not-yet-settled connection to find which one a datagram belongs to.
pub fn local_ufrag(datagram: &[u8]) -> Option<String> {
    if !is_stun_message(datagram) {
        return None;
    }

    let mut message = Message::new();
    message.unmarshal_binary(datagram).ok()?;
    let username = Username::get_from_as(&message, ATTR_USERNAME).ok()?;
    let (local, _remote) = username.text.split_once(':')?;
    Some(local.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtc::stun::message::{BINDING_REQUEST, Setter, TransactionId};

    fn binding_request(username: &str) -> Vec<u8> {
        let mut message = Message::new();
        message.typ = BINDING_REQUEST;
        message.transaction_id = TransactionId::new();
        Username::new(ATTR_USERNAME, username.to_string())
            .add_to(&mut message)
            .unwrap();
        message.write_header();
        message.raw.clone()
    }

    #[test]
    fn the_local_half_of_the_username_is_returned() {
        let datagram = binding_request("abcd:wxyz");
        assert_eq!(local_ufrag(&datagram).as_deref(), Some("abcd"));
    }

    #[test]
    fn a_non_stun_datagram_has_none() {
        assert_eq!(local_ufrag(b"not a stun message"), None);
    }

    #[test]
    fn a_username_without_a_colon_has_none() {
        let datagram = binding_request("no-colon-here");
        assert_eq!(local_ufrag(&datagram), None);
    }
}
