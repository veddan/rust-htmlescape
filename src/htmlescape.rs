use std::io::{Write, BufRead, Cursor};
use std::io;
use std::char;
use self::DecodeState::*;
use io_support::write_char;
use io_support;

static NAMED_ENTITIES: &'static[(&'static str, char)] = &[
    ("AElig", '\u{00C6}'),
    ("Aacute", '\u{00C1}'),
    ("Acirc", '\u{00C2}'),
    ("Agrave", '\u{00C0}'),
    ("Alpha", '\u{0391}'),
    ("Aring", '\u{00C5}'),
    ("Atilde", '\u{00C3}'),
    ("Auml", '\u{00C4}'),
    ("Beta", '\u{0392}'),
    ("Ccedil", '\u{00C7}'),
    ("Chi", '\u{03A7}'),
    ("Dagger", '\u{2021}'),
    ("Delta", '\u{0394}'),
    ("ETH", '\u{00D0}'),
    ("Eacute", '\u{00C9}'),
    ("Ecirc", '\u{00CA}'),
    ("Egrave", '\u{00C8}'),
    ("Epsilon", '\u{0395}'),
    ("Eta", '\u{0397}'),
    ("Euml", '\u{00CB}'),
    ("Gamma", '\u{0393}'),
    ("Iacute", '\u{00CD}'),
    ("Icirc", '\u{00CE}'),
    ("Igrave", '\u{00CC}'),
    ("Iota", '\u{0399}'),
    ("Iuml", '\u{00CF}'),
    ("Kappa", '\u{039A}'),
    ("Lambda", '\u{039B}'),
    ("Mu", '\u{039C}'),
    ("Ntilde", '\u{00D1}'),
    ("Nu", '\u{039D}'),
    ("OElig", '\u{0152}'),
    ("Oacute", '\u{00D3}'),
    ("Ocirc", '\u{00D4}'),
    ("Ograve", '\u{00D2}'),
    ("Omega", '\u{03A9}'),
    ("Omicron", '\u{039F}'),
    ("Oslash", '\u{00D8}'),
    ("Otilde", '\u{00D5}'),
    ("Ouml", '\u{00D6}'),
    ("Phi", '\u{03A6}'),
    ("Pi", '\u{03A0}'),
    ("Prime", '\u{2033}'),
    ("Psi", '\u{03A8}'),
    ("Rho", '\u{03A1}'),
    ("Scaron", '\u{0160}'),
    ("Sigma", '\u{03A3}'),
    ("THORN", '\u{00DE}'),
    ("Tau", '\u{03A4}'),
    ("Theta", '\u{0398}'),
    ("Uacute", '\u{00DA}'),
    ("Ucirc", '\u{00DB}'),
    ("Ugrave", '\u{00D9}'),
    ("Upsilon", '\u{03A5}'),
    ("Uuml", '\u{00DC}'),
    ("Xi", '\u{039E}'),
    ("Yacute", '\u{00DD}'),
    ("Yuml", '\u{0178}'),
    ("Zeta", '\u{0396}'),
    ("aacute", '\u{00E1}'),
    ("acirc", '\u{00E2}'),
    ("acute", '\u{00B4}'),
    ("aelig", '\u{00E6}'),
    ("agrave", '\u{00E0}'),
    ("alefsym", '\u{2135}'),
    ("alpha", '\u{03B1}'),
    ("amp", '\u{0026}'),
    ("and", '\u{2227}'),
    ("ang", '\u{2220}'),
    ("aring", '\u{00E5}'),
    ("asymp", '\u{2248}'),
    ("atilde", '\u{00E3}'),
    ("auml", '\u{00E4}'),
    ("bdquo", '\u{201E}'),
    ("beta", '\u{03B2}'),
    ("brvbar", '\u{00A6}'),
    ("bull", '\u{2022}'),
    ("cap", '\u{2229}'),
    ("ccedil", '\u{00E7}'),
    ("cedil", '\u{00B8}'),
    ("cent", '\u{00A2}'),
    ("chi", '\u{03C7}'),
    ("circ", '\u{02C6}'),
    ("clubs", '\u{2663}'),
    ("cong", '\u{2245}'),
    ("copy", '\u{00A9}'),
    ("crarr", '\u{21B5}'),
    ("cup", '\u{222A}'),
    ("curren", '\u{00A4}'),
    ("dArr", '\u{21D3}'),
    ("dagger", '\u{2020}'),
    ("darr", '\u{2193}'),
    ("deg", '\u{00B0}'),
    ("delta", '\u{03B4}'),
    ("diams", '\u{2666}'),
    ("divide", '\u{00F7}'),
    ("eacute", '\u{00E9}'),
    ("ecirc", '\u{00EA}'),
    ("egrave", '\u{00E8}'),
    ("empty", '\u{2205}'),
    ("emsp", '\u{2003}'),
    ("ensp", '\u{2002}'),
    ("epsilon", '\u{03B5}'),
    ("equiv", '\u{2261}'),
    ("eta", '\u{03B7}'),
    ("eth", '\u{00F0}'),
    ("euml", '\u{00EB}'),
    ("euro", '\u{20AC}'),
    ("exist", '\u{2203}'),
    ("fnof", '\u{0192}'),
    ("forall", '\u{2200}'),
    ("frac12", '\u{00BD}'),
    ("frac14", '\u{00BC}'),
    ("frac34", '\u{00BE}'),
    ("frasl", '\u{2044}'),
    ("gamma", '\u{03B3}'),
    ("ge", '\u{2265}'),
    ("gt", '\u{003E}'),
    ("hArr", '\u{21D4}'),
    ("harr", '\u{2194}'),
    ("hearts", '\u{2665}'),
    ("hellip", '\u{2026}'),
    ("iacute", '\u{00ED}'),
    ("icirc", '\u{00EE}'),
    ("iexcl", '\u{00A1}'),
    ("igrave", '\u{00EC}'),
    ("image", '\u{2111}'),
    ("infin", '\u{221E}'),
    ("int", '\u{222B}'),
    ("iota", '\u{03B9}'),
    ("iquest", '\u{00BF}'),
    ("isin", '\u{2208}'),
    ("iuml", '\u{00EF}'),
    ("kappa", '\u{03BA}'),
    ("lArr", '\u{21D0}'),
    ("lambda", '\u{03BB}'),
    ("lang", '\u{2329}'),
    ("laquo", '\u{00AB}'),
    ("larr", '\u{2190}'),
    ("lceil", '\u{2308}'),
    ("ldquo", '\u{201C}'),
    ("le", '\u{2264}'),
    ("lfloor", '\u{230A}'),
    ("lowast", '\u{2217}'),
    ("loz", '\u{25CA}'),
    ("lrm", '\u{200E}'),
    ("lsaquo", '\u{2039}'),
    ("lsquo", '\u{2018}'),
    ("lt", '\u{003C}'),
    ("macr", '\u{00AF}'),
    ("mdash", '\u{2014}'),
    ("micro", '\u{00B5}'),
    ("middot", '\u{00B7}'),
    ("minus", '\u{2212}'),
    ("mu", '\u{03BC}'),
    ("nabla", '\u{2207}'),
    ("nbsp", '\u{00A0}'),
    ("ndash", '\u{2013}'),
    ("ne", '\u{2260}'),
    ("ni", '\u{220B}'),
    ("not", '\u{00AC}'),
    ("notin", '\u{2209}'),
    ("nsub", '\u{2284}'),
    ("ntilde", '\u{00F1}'),
    ("nu", '\u{03BD}'),
    ("oacute", '\u{00F3}'),
    ("ocirc", '\u{00F4}'),
    ("oelig", '\u{0153}'),
    ("ograve", '\u{00F2}'),
    ("oline", '\u{203E}'),
    ("omega", '\u{03C9}'),
    ("omicron", '\u{03BF}'),
    ("oplus", '\u{2295}'),
    ("or", '\u{2228}'),
    ("ordf", '\u{00AA}'),
    ("ordm", '\u{00BA}'),
    ("oslash", '\u{00F8}'),
    ("otilde", '\u{00F5}'),
    ("otimes", '\u{2297}'),
    ("ouml", '\u{00F6}'),
    ("para", '\u{00B6}'),
    ("part", '\u{2202}'),
    ("permil", '\u{2030}'),
    ("perp", '\u{22A5}'),
    ("phi", '\u{03C6}'),
    ("pi", '\u{03C0}'),
    ("piv", '\u{03D6}'),
    ("plusmn", '\u{00B1}'),
    ("pound", '\u{00A3}'),
    ("prime", '\u{2032}'),
    ("prod", '\u{220F}'),
    ("prop", '\u{221D}'),
    ("psi", '\u{03C8}'),
    ("quot", '\u{0022}'),
    ("rArr", '\u{21D2}'),
    ("radic", '\u{221A}'),
    ("rang", '\u{232A}'),
    ("raquo", '\u{00BB}'),
    ("rarr", '\u{2192}'),
    ("rceil", '\u{2309}'),
    ("rdquo", '\u{201D}'),
    ("real", '\u{211C}'),
    ("reg", '\u{00AE}'),
    ("rfloor", '\u{230B}'),
    ("rho", '\u{03C1}'),
    ("rlm", '\u{200F}'),
    ("rsaquo", '\u{203A}'),
    ("rsquo", '\u{2019}'),
    ("sbquo", '\u{201A}'),
    ("scaron", '\u{0161}'),
    ("sdot", '\u{22C5}'),
    ("sect", '\u{00A7}'),
    ("shy", '\u{00AD}'),
    ("sigma", '\u{03C3}'),
    ("sigmaf", '\u{03C2}'),
    ("sim", '\u{223C}'),
    ("spades", '\u{2660}'),
    ("sub", '\u{2282}'),
    ("sube", '\u{2286}'),
    ("sum", '\u{2211}'),
    ("sup", '\u{2283}'),
    ("sup1", '\u{00B9}'),
    ("sup2", '\u{00B2}'),
    ("sup3", '\u{00B3}'),
    ("supe", '\u{2287}'),
    ("szlig", '\u{00DF}'),
    ("tau", '\u{03C4}'),
    ("there4", '\u{2234}'),
    ("theta", '\u{03B8}'),
    ("thetasym", '\u{03D1}'),
    ("thinsp", '\u{2009}'),
    ("thorn", '\u{00FE}'),
    ("tilde", '\u{02DC}'),
    ("times", '\u{00D7}'),
    ("trade", '\u{2122}'),
    ("uArr", '\u{21D1}'),
    ("uacute", '\u{00FA}'),
    ("uarr", '\u{2191}'),
    ("ucirc", '\u{00FB}'),
    ("ugrave", '\u{00F9}'),
    ("uml", '\u{00A8}'),
    ("upsih", '\u{03D2}'),
    ("upsilon", '\u{03C5}'),
    ("uuml", '\u{00FC}'),
    ("weierp", '\u{2118}'),
    ("xi", '\u{03BE}'),
    ("yacute", '\u{00FD}'),
    ("yen", '\u{00A5}'),
    ("yuml", '\u{00FF}'),
    ("zeta", '\u{03B6}'),
    ("zwj", '\u{200D}'),
    ("zwnj", '\u{200C}'),
];

static MINIMAL_ENTITIES: [(char, &'static str); 5] = [
    ('"', "&quot;"),
    ('&', "&amp;"),
    ('\'', "&#x27;"),
    ('<', "&lt;"),
    ('>', "&gt;")
];

fn get_entity(c: char) -> Option<&'static str> {
    match MINIMAL_ENTITIES.binary_search_by(|&(ec, _)| ec.cmp(&c) ) {
        Err(..) => None,
        Ok(idx) => {
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
/// assert_eq!(&encoded, "&lt;em&gt;Hej!&lt;/em&gt;");
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
    let mut writer = Vec::with_capacity((s.len()/3 + 1) * 4);
    match encode_minimal_w(s, &mut writer) {
        Err(_) => panic!(),
        Ok(_) => String::from_utf8(writer).unwrap()
    }
}

///
/// HTML entity-encode a string.
///
/// Similar to `encode_minimal`, except that the output is written to a writer rather
/// than returned as a `String`.
///
/// # Arguments
/// - `s` - The string to encode.
/// - `writer` - Output is written to here.
pub fn encode_minimal_w<W: Write>(s: &str, writer: &mut W) -> io::Result<()> {
    for c in s.chars() {
        match get_entity(c) {
            None => try!(write_char(writer, c)),
            Some(entity) => try!(writer.write_all(entity.as_bytes()))
        }
    }
    Ok(())
}

fn write_hex<W: Write>(writer: &mut W, c: char) -> io::Result<()> {
    let hex = b"0123456789ABCDEF";
    try!(writer.write(b"&#x"));
    let n = c as u8;
    let bytes = [hex[((n & 0xF0) >> 4) as usize],
                 hex[(n & 0x0F) as usize],
                 b';'];
    writer.write_all(&bytes)
}

fn is_ascii_alnum(c: char) -> bool {
    (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
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
/// assert_eq!(&encoded, "&quot;No&quot;&#x2C;&#x20;he&#x20;said&#x2E;");
/// ~~~
pub fn encode_attribute(s: &str) -> String {
    let mut writer = Vec::with_capacity(s.len() * 3);
    match encode_attribute_w(s, &mut writer) {
        Err(_) => panic!(),
        Ok(_) => String::from_utf8(writer).unwrap()
    }
}

///
/// HTML entity-encodes a string for use in attributes values.
///
/// Similar to `encode_attribute`, except that the output is written to a writer rather
/// than returned as a `String`.
///
/// # Arguments
/// - `s` - The string to encode.
/// - `writer` - Output is written to here.
pub fn encode_attribute_w<W: Write>(s: &str, writer: &mut W) -> io::Result<()> {
    for c in s.chars() {
        let b = c as usize;
        let res = match get_entity(c) {
            Some(entity) => writer.write_all(entity.as_bytes()),
            None =>
                if b < 256 && (b > 127 || !is_ascii_alnum(c)) {
                    write_hex(writer, c)
                } else {
                    write_char(writer, c)
                }
        };
        try!(res);
    }
    Ok(())
}

#[derive(PartialEq, Eq)]
enum DecodeState {
    Normal,
    Entity,
    Named,
    Numeric,
    Hex,
    Dec
}

fn decode_named_entity(entity: &str) -> Result<char, String> {
    match NAMED_ENTITIES.binary_search_by(|&(ent, _)| ent.cmp(entity)) {
        Err(..) => Err(format!("no such entity '&{};", entity)),
        Ok(idx) => {
            let (_, c) = NAMED_ENTITIES[idx];
            Ok(c)
        }
    }
}

fn decode_numeric(esc: &str, radix: u32) -> Result<char, String> {
    match u32::from_str_radix(esc, radix) {
        Ok(n) => match char::from_u32(n) {
            Some(c) => Ok(c),
            None => Err(format!("invalid character '{}' in \"{}\"", n, esc))
        },
        Err(..) => Err(format!("invalid escape \"{}\"", esc))
    }
}

macro_rules! try_parse(
    ($parse:expr, $pos:ident) => (
        match $parse {
            Err(reason) => return Err(format!("at {}: {}", $pos, reason)),
            Ok(res) => res
        }
    ););

macro_rules! do_io(
    ($io:expr) => (
        match $io {
            Err(e) => return Err(e.to_string()),
            Ok(_) => ()
        }
    ););

/// Decodes an entity-encoded string.
///
/// Similar to `decode_html`, except reading from a reader rather than a string, and
/// writing to a writer rather than returning a `String`.
///
/// # Arguments
/// - `reader` - Encoded data is read from here.
/// - `writer` - Decoded data is written to here.
///
/// # Return value
/// On success `Ok(())` is returned. On error, `Err(reason)` is returned, with `reason`
/// containing a description of the error.
pub fn decode_html_rw<R: BufRead, W: Write>(reader: R, writer: &mut W) -> Result<(), String> {
    let mut state: DecodeState = Normal;
    let mut pos = 0;
    let mut buf = String::with_capacity(8);
    for c in io_support::chars(reader) {
        let c = match c {
            Ok(c) => c,
            Err(e) => return Err(e.to_string())
        };
        match state {
            Normal if c == '&' => state = Entity,
            Normal => do_io!(write_char(writer, c)),
            Entity if c == '#' => state = Numeric,
            Entity => {
                state = Named;
                buf.push(c);
            }
            Named if c == ';' => {
                state = Normal;
                let ch = try_parse!(decode_named_entity(&buf), pos);
                do_io!(write_char(writer, ch));
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
                let ch = try_parse!(decode_numeric(&buf, 10), pos);
                do_io!(write_char(writer, ch));
                buf.clear();
            }
            Hex if c == ';' => {
                state = Normal;
                let ch = try_parse!(decode_numeric(&buf, 16), pos);
                do_io!(write_char(writer, ch));
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
    let mut writer = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut reader = Cursor::new(bytes);
    let res = decode_html_rw(&mut reader, &mut writer);
    match res {
        Ok(_) => Ok(String::from_utf8(writer).unwrap()),
        Err(err) => Err(err)
    }
}

fn is_digit(c: char) -> bool { c >= '0' && c <= '9' }

fn is_hex_digit(c: char) -> bool { is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')  }

