use std::collections::HashMap;

pub fn escape_control_chars<T: AsRef<str>>(input: T) -> String {
    input
        .as_ref()
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace(';', "%3B")
}

pub fn parse_kv(values: &[u8], separator: u8) -> HashMap<&[u8], &[u8]> {
    let mut hm = HashMap::new();
    for sub in values.split(|c| *c == separator) {
        let kv = sub.split(|c| *c == b'=').collect::<Vec<_>>();
        hm.insert(kv[0], kv[1]);
    }

    hm
}

pub fn encode_kv(hm: HashMap<&str, &str>) -> String {
    let email = escape_control_chars(*hm.get("email").unwrap());
    let uid = escape_control_chars(*hm.get("uid").unwrap());
    let role = escape_control_chars(*hm.get("role").unwrap());
    format!("email={}&uid={}&role={}", email, uid, role)
}
