
extern crate htmlescape;

extern crate num;
extern crate rand;

use std::char;

use htmlescape::*;

macro_rules! assert_typed_eq (($T: ty, $given: expr, $expected: expr) => ({
    let given_val: &$T = $given;
    let expected_val: &$T = $expected;
    assert_eq!(given_val, expected_val);
}));

#[test]
fn test_encode_minimal() {
    let data = [
        // (input, expected_output)
        ("", ""),
        ("Håll älgen, Örjan!", "Håll älgen, Örjan!"),
        ("<p>hej!</p>", "&lt;p&gt;hej!&lt;/p&gt;"),
        ("bread & butter", "bread &amp; butter"),
        ("\"bread\" & butter", "&quot;bread&quot; &amp; butter"),
        ("< less than", "&lt; less than"),
        ("greater than >", "greater than &gt;"),
        ];

    for &(input, expected) in data.iter() {
        let actual = encode_minimal(input);
        assert_eq!(&actual, expected);
    }
}

#[test]
fn test_encode_attribute() {
    let data = [
        ("", ""),
        ("0 3px", "0&#x20;3px"),
        ("<img \"\"\">", "&lt;img&#x20;&quot;&quot;&quot;&gt;"),
        ("hej; hå", "hej&#x3B;&#x20;h&#xE5;"),
        ];
    for &(input, expected) in data.iter() {
        let actual = encode_attribute(input);
        assert_eq!(&actual, expected);
    }
}

#[test]
fn test_decode() {
    let data = [
        ("", ""),
        ("Håll älgen, Örjan!", "Håll älgen, Örjan!"),
        ("&lt;p&gt;hej!&lt;/p&gt;", "<p>hej!</p>"),
        ("hej&#x3B;&#x20;hå", "hej; hå"),
        ("&quot;width&#x3A;&#32;3px&#59;&quot;", "\"width: 3px;\""),
        ("&#x2b;", "+"),
        ];
    for &(input, expected) in data.iter() {
        match decode_html(input) {
            Ok(actual) => assert_eq!(&actual, expected),
            Err(reason) => panic!("Failed at \"{}\", reason \"{}\"", input, reason)
        }
    }
}

#[test]
fn bad_decode() {
    let data = [
        "&thisisareallylongentityname;",
        "&#-1;",
        "&#x13eQ;",
        "&quot ;",
        "&&gt;",
        "&;",
        "&#;",
        "&#x",
        ];
    for &input in data.iter() {
        match decode_html(input) {
            Err(_) => (),
            Ok(res) => panic!("Failed at \"{}\", expected error, got \"{}\"", input, res)
        }
    }
}

#[test]
fn random_roundtrip() {
    let mut rng = rand::weak_rng();
    for _ in 1..100 {
        let original = random_str(&mut rng);
        let encoded = encode_attribute(&original);
        match decode_html(&encoded) {
            Err(reason) => panic!("error at \"{}\", reason: {}", original, reason),
            Ok(decoded) => assert_eq!(original, decoded)
        };
    }
}


fn random_str<R: rand::Rng>(rng: &mut R) -> String {
    let len = rng.gen_range::<usize>(0, 40);
    let mut s = String::new();
    for _ in 0..len {
        let c = char::from_u32(rng.gen_range::<usize>(1, 512) as u32).unwrap();
        s.push(c);
    }
    return s;
}

