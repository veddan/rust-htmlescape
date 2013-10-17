#[link(name = "htmlescape",
       vers = "0.1.0",
       author = "Viktor Dahl",
       url = "https://github.com/veddan/rust-htmlescape")];

#[comment = "HTML entity-encoding/decoding library"];
#[crate_type = "lib"];

#[feature(globs)];
#[feature(macro_rules)];

#[cfg(test)]
extern mod extra;

pub mod htmlescape;

