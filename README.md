# A HTML entity encoding library for Rust
## Example usage
All example assume a `use htmlescape::*;` is present.

```
let title = "Cats > dogs";
let tag = fmt!("<title>%s</title>", encode_minimal(title));
assert\_eq!(tag, `"<title>Cats &amp; dogs</title>");
```

```
let encoded = "Cats&#x20;&amp;&#32;dogs";
let decoded = match decode_html(encoded) {
  Err(reason) => fail!("Something went wrong: %s", reason),
  Ok(s) => s
};
assert_eq!(~"Cats > dogs", decoded);
```
