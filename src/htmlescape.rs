use std::io::{Writer, Buffer, MemWriter, BufReader, IoResult};
use std::io;
use std::{num, char};
use std::slice::{Found, NotFound};

static NAMED_ENTITIES: &'static[(&'static str, char)] = &[
    ("AElig", '\u00C6'),
    ("Aacute", '\u00C1'),
    ("Acirc", '\u00C2'),
    ("Agrave", '\u00C0'),
    ("Alpha", '\u0391'),
    ("Aring", '\u00C5'),
    ("Atilde", '\u00C3'),
    ("Auml", '\u00C4'),
    ("Beta", '\u0392'),
    ("Ccedil", '\u00C7'),
    ("Chi", '\u03A7'),
    ("Dagger", '\u2021'),
    ("Delta", '\u0394'),
    ("ETH", '\u00D0'),
    ("Eacute", '\u00C9'),
    ("Ecirc", '\u00CA'),
    ("Egrave", '\u00C8'),
    ("Epsilon", '\u0395'),
    ("Eta", '\u0397'),
    ("Euml", '\u00CB'),
    ("Gamma", '\u0393'),
    ("Iacute", '\u00CD'),
    ("Icirc", '\u00CE'),
    ("Igrave", '\u00CC'),
    ("Iota", '\u0399'),
    ("Iuml", '\u00CF'),
    ("Kappa", '\u039A'),
    ("Lambda", '\u039B'),
    ("Mu", '\u039C'),
    ("Ntilde", '\u00D1'),
    ("Nu", '\u039D'),
    ("OElig", '\u0152'),
    ("Oacute", '\u00D3'),
    ("Ocirc", '\u00D4'),
    ("Ograve", '\u00D2'),
    ("Omega", '\u03A9'),
    ("Omicron", '\u039F'),
    ("Oslash", '\u00D8'),
    ("Otilde", '\u00D5'),
    ("Ouml", '\u00D6'),
    ("Phi", '\u03A6'),
    ("Pi", '\u03A0'),
    ("Prime", '\u2033'),
    ("Psi", '\u03A8'),
    ("Rho", '\u03A1'),
    ("Scaron", '\u0160'),
    ("Sigma", '\u03A3'),
    ("THORN", '\u00DE'),
    ("Tau", '\u03A4'),
    ("Theta", '\u0398'),
    ("Uacute", '\u00DA'),
    ("Ucirc", '\u00DB'),
    ("Ugrave", '\u00D9'),
    ("Upsilon", '\u03A5'),
    ("Uuml", '\u00DC'),
    ("Xi", '\u039E'),
    ("Yacute", '\u00DD'),
    ("Yuml", '\u0178'),
    ("Zeta", '\u0396'),
    ("aacute", '\u00E1'),
    ("acirc", '\u00E2'),
    ("acute", '\u00B4'),
    ("aelig", '\u00E6'),
    ("agrave", '\u00E0'),
    ("alefsym", '\u2135'),
    ("alpha", '\u03B1'),
    ("amp", '\u0026'),
    ("and", '\u2227'),
    ("ang", '\u2220'),
    ("aring", '\u00E5'),
    ("asymp", '\u2248'),
    ("atilde", '\u00E3'),
    ("auml", '\u00E4'),
    ("bdquo", '\u201E'),
    ("beta", '\u03B2'),
    ("brvbar", '\u00A6'),
    ("bull", '\u2022'),
    ("cap", '\u2229'),
    ("ccedil", '\u00E7'),
    ("cedil", '\u00B8'),
    ("cent", '\u00A2'),
    ("chi", '\u03C7'),
    ("circ", '\u02C6'),
    ("clubs", '\u2663'),
    ("cong", '\u2245'),
    ("copy", '\u00A9'),
    ("crarr", '\u21B5'),
    ("cup", '\u222A'),
    ("curren", '\u00A4'),
    ("dArr", '\u21D3'),
    ("dagger", '\u2020'),
    ("darr", '\u2193'),
    ("deg", '\u00B0'),
    ("delta", '\u03B4'),
    ("diams", '\u2666'),
    ("divide", '\u00F7'),
    ("eacute", '\u00E9'),
    ("ecirc", '\u00EA'),
    ("egrave", '\u00E8'),
    ("empty", '\u2205'),
    ("emsp", '\u2003'),
    ("ensp", '\u2002'),
    ("epsilon", '\u03B5'),
    ("equiv", '\u2261'),
    ("eta", '\u03B7'),
    ("eth", '\u00F0'),
    ("euml", '\u00EB'),
    ("euro", '\u20AC'),
    ("exist", '\u2203'),
    ("fnof", '\u0192'),
    ("forall", '\u2200'),
    ("frac12", '\u00BD'),
    ("frac14", '\u00BC'),
    ("frac34", '\u00BE'),
    ("frasl", '\u2044'),
    ("gamma", '\u03B3'),
    ("ge", '\u2265'),
    ("gt", '\u003E'),
    ("hArr", '\u21D4'),
    ("harr", '\u2194'),
    ("hearts", '\u2665'),
    ("hellip", '\u2026'),
    ("iacute", '\u00ED'),
    ("icirc", '\u00EE'),
    ("iexcl", '\u00A1'),
    ("igrave", '\u00EC'),
    ("image", '\u2111'),
    ("infin", '\u221E'),
    ("int", '\u222B'),
    ("iota", '\u03B9'),
    ("iquest", '\u00BF'),
    ("isin", '\u2208'),
    ("iuml", '\u00EF'),
    ("kappa", '\u03BA'),
    ("lArr", '\u21D0'),
    ("lambda", '\u03BB'),
    ("lang", '\u2329'),
    ("laquo", '\u00AB'),
    ("larr", '\u2190'),
    ("lceil", '\u2308'),
    ("ldquo", '\u201C'),
    ("le", '\u2264'),
    ("lfloor", '\u230A'),
    ("lowast", '\u2217'),
    ("loz", '\u25CA'),
    ("lrm", '\u200E'),
    ("lsaquo", '\u2039'),
    ("lsquo", '\u2018'),
    ("lt", '\u003C'),
    ("macr", '\u00AF'),
    ("mdash", '\u2014'),
    ("micro", '\u00B5'),
    ("middot", '\u00B7'),
    ("minus", '\u2212'),
    ("mu", '\u03BC'),
    ("nabla", '\u2207'),
    ("nbsp", '\u00A0'),
    ("ndash", '\u2013'),
    ("ne", '\u2260'),
    ("ni", '\u220B'),
    ("not", '\u00AC'),
    ("notin", '\u2209'),
    ("nsub", '\u2284'),
    ("ntilde", '\u00F1'),
    ("nu", '\u03BD'),
    ("oacute", '\u00F3'),
    ("ocirc", '\u00F4'),
    ("oelig", '\u0153'),
    ("ograve", '\u00F2'),
    ("oline", '\u203E'),
    ("omega", '\u03C9'),
    ("omicron", '\u03BF'),
    ("oplus", '\u2295'),
    ("or", '\u2228'),
    ("ordf", '\u00AA'),
    ("ordm", '\u00BA'),
    ("oslash", '\u00F8'),
    ("otilde", '\u00F5'),
    ("otimes", '\u2297'),
    ("ouml", '\u00F6'),
    ("para", '\u00B6'),
    ("part", '\u2202'),
    ("permil", '\u2030'),
    ("perp", '\u22A5'),
    ("phi", '\u03C6'),
    ("pi", '\u03C0'),
    ("piv", '\u03D6'),
    ("plusmn", '\u00B1'),
    ("pound", '\u00A3'),
    ("prime", '\u2032'),
    ("prod", '\u220F'),
    ("prop", '\u221D'),
    ("psi", '\u03C8'),
    ("quot", '\u0022'),
    ("rArr", '\u21D2'),
    ("radic", '\u221A'),
    ("rang", '\u232A'),
    ("raquo", '\u00BB'),
    ("rarr", '\u2192'),
    ("rceil", '\u2309'),
    ("rdquo", '\u201D'),
    ("real", '\u211C'),
    ("reg", '\u00AE'),
    ("rfloor", '\u230B'),
    ("rho", '\u03C1'),
    ("rlm", '\u200F'),
    ("rsaquo", '\u203A'),
    ("rsquo", '\u2019'),
    ("sbquo", '\u201A'),
    ("scaron", '\u0161'),
    ("sdot", '\u22C5'),
    ("sect", '\u00A7'),
    ("shy", '\u00AD'),
    ("sigma", '\u03C3'),
    ("sigmaf", '\u03C2'),
    ("sim", '\u223C'),
    ("spades", '\u2660'),
    ("sub", '\u2282'),
    ("sube", '\u2286'),
    ("sum", '\u2211'),
    ("sup", '\u2283'),
    ("sup1", '\u00B9'),
    ("sup2", '\u00B2'),
    ("sup3", '\u00B3'),
    ("supe", '\u2287'),
    ("szlig", '\u00DF'),
    ("tau", '\u03C4'),
    ("there4", '\u2234'),
    ("theta", '\u03B8'),
    ("thetasym", '\u03D1'),
    ("thinsp", '\u2009'),
    ("thorn", '\u00FE'),
    ("tilde", '\u02DC'),
    ("times", '\u00D7'),
    ("trade", '\u2122'),
    ("uArr", '\u21D1'),
    ("uacute", '\u00FA'),
    ("uarr", '\u2191'),
    ("ucirc", '\u00FB'),
    ("ugrave", '\u00F9'),
    ("uml", '\u00A8'),
    ("upsih", '\u03D2'),
    ("upsilon", '\u03C5'),
    ("uuml", '\u00FC'),
    ("weierp", '\u2118'),
    ("xi", '\u03BE'),
    ("yacute", '\u00FD'),
    ("yen", '\u00A5'),
    ("yuml", '\u00FF'),
    ("zeta", '\u03B6'),
    ("zwj", '\u200D'),
    ("zwnj", '\u200C'),
];

static MINIMAL_ENTITIES: [(char, &'static str), ..5] = [
    ('"', "&quot;"),
    ('&', "&amp;"),
    ('\'', "&#x27;"),
    ('<', "&lt;"),
    ('>', "&gt;")
];

fn get_entity(c: char) -> Option<&'static str> {
    match MINIMAL_ENTITIES.binary_search(|&(ec, _)| { ec.cmp(&c) }) {
        NotFound(..) => None,
        Found(idx)   => {
            let (_, e) = MINIMAL_ENTITIES[idx];
            Some(e)
        }
    }
}

///
/// HTML entity-encode a string.
///
/// Entity-encodes a string with a minimal set of entities:
///
/// - `" -- &quot;`
/// - `& -- &amp;`
/// - `' -- &#x27;`
/// - `< -- &lt;`
/// - `> -- &gt;`
///
/// # Arguments
/// - `s` - The string to encode.
///
/// # Return value
/// The encoded string.
///
/// # Example
/// ~~~
/// let encoded = htmlescape::encode_minimal("<em>Hej!</em>");
/// assert_eq!(encoded.as_slice(), "&lt;em&gt;Hej!&lt;/em&gt;");
/// ~~~
///
/// # Safety notes
/// Using the function to encode an untrusted string that is to be used as a HTML attribute value
/// may lead to XSS vulnerabilities. Consider the following example:
///
/// ~~~
/// let name = "dummy onmouseover=alert(/XSS/)";    // User input
/// let tag = format!("<option value={}>", htmlescape::encode_minimal(name));
/// // Here `tag` is    "<option value=dummy onmouseover=alert(/XSS/)>"
/// ~~~
///
/// Use `escape_attribute` for escaping HTML attribute values.
pub fn encode_minimal(s: &str) -> String {
    let mut writer = MemWriter::with_capacity(s.len() * 4 / 3);
    match encode_minimal_w(s, &mut writer) {
        Err(_) => panic!(),
        Ok(_) => String::from_utf8(writer.unwrap()).unwrap()
    }
}

///
/// HTML entity-encode a string.
///
/// Similar to `encode_minimal`, except that the output is written to a `Writer` rather
/// than returned as a `String`.
///
/// # Arguments
/// - `s` - The string to encode.
/// - `writer` - Output is written to here.
pub fn encode_minimal_w<W: Writer>(s: &str, writer: &mut W) -> IoResult<()> {
    for c in s.chars() {
        match get_entity(c) {
            None => try!(writer.write_char(c)),
            Some(entity) => try!(writer.write(entity.as_bytes()))
        }
    }
    Ok(())
}

fn write_hex<W: Writer>(c: char, writer: &mut W) -> IoResult<()> {
    let hex = "0123456789ABCDEF".as_bytes();
    try!(writer.write("&#x".as_bytes()));
    let n = c as u8;
    try!(writer.write_u8(hex[((n & 0xF0) >> 4) as uint]));
    try!(writer.write_u8(hex[(n & 0x0F) as uint]));
    try!(writer.write_char(';'));
    Ok(())
}

///
/// HTML entity-encodes a string for use in attributes values.
///
/// Entity-encodes a string using an extensive set of entities, giving a string suitable for use
/// in HTML attribute values. All entities from `encode_minimal` are used, and further, all
/// non-alphanumeric ASCII characters are hex-encoded (`&#x__;`).
/// See the [OWASP XSS Prevention Cheat Sheet](
/// https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) for more
/// information on entity-encoding for attribute values.
///
/// # Arguments
/// - `s` - The string to encode.
///
/// # Return value
/// The encoded string.
///
/// # Example
/// ~~~
/// let encoded = htmlescape::encode_attribute("\"No\", he said.");
/// assert_eq!(encoded.as_slice(), "&quot;No&quot;&#x2C;&#x20;he&#x20;said&#x2E;");
/// ~~~
pub fn encode_attribute(s: &str) -> String {
    let mut writer = MemWriter::with_capacity(s.len() * 3);
    match encode_attribute_w(s, &mut writer) {
        Err(_) => panic!(),
        Ok(_) => String::from_utf8(writer.unwrap()).unwrap()
    }
}

///
/// HTML entity-encodes a string for use in attributes values.
///
/// Similar to `encode_attribute`, except that the output is written to a `Writer` rather
/// than returned as a `String`.
///
/// # Arguments
/// - `s` - The string to encode.
/// - `writer` - Output is written to here.
pub fn encode_attribute_w<W: Writer>(s: &str, writer: &mut W) -> IoResult<()> {
    for c in s.chars() {
        let b = c as uint;
        match get_entity(c) {
            Some(entity) => try!(writer.write(entity.as_bytes())),
            None =>
                if b < 256 && (b > 127 || unsafe { !c.to_ascii_nocheck().is_alphanumeric() }) {
                    try!(write_hex(c, writer))
                } else {
                    try!(writer.write_char(c))
                }
        }
    }
    Ok(())
}

#[deriving(PartialEq, Eq)]
enum DecodeState {
    Normal,
    Entity,
    Named,
    Numeric,
    Hex,
    Dec
}

fn decode_named_entity(entity: &str) -> Result<char, String> {
    match NAMED_ENTITIES.binary_search(|&(ent, _)| {ent.cmp(entity) }) {
        NotFound(..) => Err(format!("no such entity '&{};", entity)),
        Found(idx)   => {
            let (_, c) = NAMED_ENTITIES[idx];
            Ok(c)
        }
    }
}

fn decode_numeric(esc: &str, radix: uint) -> Result<char, String> {
    match num::from_str_radix::<u32>(esc, radix) {
        Some(n) => match char::from_u32(n) {
            Some(c) => Ok(c),
            None => Err(format!("invalid character '{}' in \"{}\"", n, esc))
        },
        None => Err(format!("invalid escape \"{}\"", esc))
    }
}

macro_rules! try_parse(
    ($parse:expr, $pos:ident) => (
        match $parse {
            Err(reason) => return Err(format!("at {}: {}", $pos, reason)),
            Ok(res) => res
        }
    );)

macro_rules! do_io(
    ($io:expr) => (
        match $io {
            Err(e) => return Err(e.to_string()),
            Ok(_) => ()
        }
    );)

/// Decodes an entity-encoded string.
///
/// Similar to `decode_html`, except reading from a `Reader` rather than a string, and
/// writing to a writer rather than returning a `String`.
///
/// # Arguments
/// - `reader` - Encoded data is read from here.
/// - `writer` - Decoded data is written to here.
///
/// # Return value
/// On success `Ok(())` is returned. On error, `Err(reason)` is returned, with `reason`
/// containing a description of the error.
pub fn decode_html_rw<R: Buffer, W: Writer>(reader: &mut R, writer: &mut W) -> Result<(), String> {
    let mut state: DecodeState = Normal;
    let mut pos = 0u;
    let mut buf = String::new();
    buf.reserve(8);
    loop {
        let c = match reader.read_char() {
            Ok(c) => c,
            Err(ref e) if e.kind == io::EndOfFile => break,
            Err(e) => return Err(e.to_string())
        };
        match state {
            Normal if c == '&' => state = Entity,
            Normal => do_io!(writer.write_char(c)),
            Entity if c == '#' => state = Numeric,
            Entity => {
                state = Named;
                buf.push(c);
            }
            Named if c == ';' => {
                state = Normal;
                let ch = try_parse!(decode_named_entity(buf.as_slice()), pos);
                do_io!(writer.write_char(ch));
                buf.clear();
            }
            Named => buf.push(c),
            Numeric if is_digit(c) => {
                state = Dec;
                buf.push(c);
            }
            Numeric if c == 'x' => state = Hex,
            Dec if c == ';' => {
                state = Normal;
                let ch = try_parse!(decode_numeric(buf.as_slice(), 10), pos);
                do_io!(writer.write_char(ch));
                buf.clear();
            }
            Hex if c == ';' => {
                state = Normal;
                let ch = try_parse!(decode_numeric(buf.as_slice(), 16), pos);
                do_io!(writer.write_char(ch));
                buf.clear();
            }
            Hex if is_hex_digit(c) => buf.push(c),
            Dec if is_digit(c) => buf.push(c),
            _ => return Err(format!("at {}: parse error", pos))
        }
        pos += 1;
    }
    if state != Normal {
        Err(format!("unfinished entity \"{}\"", buf))
    } else {
        Ok(())
    }
}

/// Decodes an entity-encoded string.
///
/// Decodes an entity encoded string, replacing HTML entities (`&amp;`, `&#20;` ...) with the
/// the corresponding character. Case matters for named entities, ie. `&Amp;` is invalid.
/// Case does not matter for hex entities, so `&#x2E;` and `&#x2e;` are treated the same.
///
/// # Arguments
/// - `s` - Entity-encoded string to decode.
///
/// # Return value
/// On success `Ok(decoded)` is returned, with `decoded` being the decoded string.
/// On error `Err(reason)` is returned, with `reason` containing a description of the error.
///
/// # Failure
/// The function will fail if input string contains invalid named entities (eg. `&nosuchentity;`),
/// invalid hex entities (eg. `&#xRT;`), invalid decimal entities (eg. `&#-1;), unclosed entities
/// (`s == "&amp hej och hå"`) or otherwise malformed entities.
pub fn decode_html(s: &str) -> Result<String, String> {
    let mut writer = MemWriter::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut reader = BufReader::new(bytes.as_slice());
    let res = decode_html_rw(&mut reader, &mut writer);
    match res {
        Ok(_) => Ok(String::from_utf8(writer.unwrap()).unwrap()),
        Err(err) => Err(err)
    }
}

fn is_digit(c: char) -> bool { c >= '0' && c <= '9' }

fn is_hex_digit(c: char) -> bool { is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')  }

#[cfg(test)]
mod test {
    extern crate test;

    use std::rand;
    use std::char;

    use htmlescape::*;

    static BIG_STR: &'static str = include_str!("../moonstone-short.txt");

    macro_rules! assert_typed_eq (($T: ty, $given: expr, $expected: expr) => ({
        let given_val: &$T = $given;
        let expected_val: &$T = $expected;
        assert_eq!(given_val, expected_val);
    }))

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
            assert_eq!(actual.as_slice(), expected);
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
            assert_eq!(actual.as_slice(), expected);
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
                Ok(actual) => assert_eq!(actual.as_slice(), expected),
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
        for _ in range(1u, 100) {
            let original = random_str(&mut rng);
            let encoded = encode_attribute(original.as_slice());
            match decode_html(encoded.as_slice()) {
                Err(reason) => panic!("error at \"{}\", reason: {}", original, reason),
                Ok(decoded) => assert_eq!(original, decoded)
            };
        }
    }

    #[bench]
    fn bench_encode_attribute(bh: &mut test::Bencher) {
        bh.iter(|| { encode_attribute(BIG_STR) });
        bh.bytes = BIG_STR.len() as u64;
    }

    #[bench]
    fn bench_encode_minimal(bh: &mut test::Bencher) {
        bh.iter(|| { encode_minimal(BIG_STR) });
        bh.bytes = BIG_STR.len() as u64;
    }

    #[bench]
    fn bench_decode_attribute(bh: &mut test::Bencher) {
        let encoded = encode_attribute(BIG_STR);
        bh.iter(|| { decode_html(encoded.as_slice()) });
        bh.bytes = encoded.len() as u64;
    }

    #[bench]
    fn bench_decode_minimal(bh: &mut test::Bencher) {
        let encoded = encode_minimal(BIG_STR);
        bh.iter(|| { decode_html(encoded.as_slice()) });
        bh.bytes = encoded.len() as u64;
    }

    fn random_str<R: rand::Rng>(rng: &mut R) -> String {
        let len = rng.gen_range::<uint>(0, 40);
        let mut s = String::new();
        for _ in range(0, len) {
            let c = char::from_u32(rng.gen_range::<uint>(1, 512) as u32).unwrap();
            s.push(c);
        }
        return s;
    }
}

