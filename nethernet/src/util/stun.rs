use rtc::stun::attributes::ATTR_USERNAME;
use rtc::stun::message::{Message, is_stun_message};
use rtc::stun::textattrs::Username;

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
