#[link(name = "htmlescape",
       vers = "0.1.0")];

#[comment = "HTML entity-encoding/decoding library"];
#[crate_type = "lib"];

#[cfg(test)]
extern mod extra;

pub mod htmlescape;
