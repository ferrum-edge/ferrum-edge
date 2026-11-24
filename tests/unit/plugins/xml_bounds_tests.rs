//! Tests for the shared pre-parse XML nesting-depth screen
//! (`plugins::utils::xml_bounds`).
//!
//! The screen was introduced because `roxmltree` before 0.21.2 recursed once
//! per open element, so a parser node budget could not keep a deeply nested
//! document from overflowing the worker stack *inside*
//! `Document::parse_with_options`. It stays the fixed nesting ceiling ahead of
//! the parser and the consumers' recursive walkers. It must be sound on raw
//! bytes: never under-count real nesting (or the bomb gets through) and never
//! over-count constructs that merely look like tags (or a legitimate document
//! is refused).

use ferrum_edge::plugins::utils::xml_bounds::{
    UnqualifiedAttribute, XML_MAX_NESTING_DEPTH, xml_nesting_depth_within_limit,
};

fn nested(levels: usize) -> String {
    let mut xml = String::with_capacity(levels * 8);
    for _ in 0..levels {
        xml.push_str("<n>");
    }
    xml.push_str("leaf");
    for _ in 0..levels {
        xml.push_str("</n>");
    }
    xml
}

#[test]
fn shared_depth_bound_is_the_documented_value() {
    assert_eq!(XML_MAX_NESTING_DEPTH, 256);
}

#[test]
fn empty_and_text_only_documents_are_within_any_limit() {
    assert!(xml_nesting_depth_within_limit("", 1));
    assert!(xml_nesting_depth_within_limit("no markup at all", 1));
}

#[test]
fn depth_is_counted_exactly_at_the_boundary() {
    assert!(xml_nesting_depth_within_limit(&nested(256), 256));
    assert!(!xml_nesting_depth_within_limit(&nested(257), 256));
}

#[test]
fn siblings_do_not_accumulate_depth() {
    let mut xml = String::from("<root>");
    for _ in 0..10_000 {
        xml.push_str("<child>x</child>");
    }
    xml.push_str("</root>");
    // A very wide document is only two levels deep; width is the node limit's
    // job, not this screen's.
    assert!(xml_nesting_depth_within_limit(&xml, 2));
}

#[test]
fn self_closing_elements_do_not_accumulate_depth() {
    let mut xml = String::from("<root>");
    for _ in 0..1_000 {
        xml.push_str("<br/>");
    }
    xml.push_str("</root>");
    assert!(xml_nesting_depth_within_limit(&xml, 2));
    // Whitespace before the slash, and attributes, must not defeat the check.
    assert!(xml_nesting_depth_within_limit(
        r#"<root><img src="x.png" alt="" /><br
/></root>"#,
        2
    ));
}

#[test]
fn tags_inside_comments_are_not_counted() {
    let mut xml = String::from("<root><!--");
    for _ in 0..600 {
        xml.push_str("<a><b><c>");
    }
    xml.push_str("--></root>");
    assert!(xml_nesting_depth_within_limit(&xml, 1));
}

#[test]
fn tags_inside_cdata_are_not_counted() {
    let mut xml = String::from("<root><![CDATA[");
    for _ in 0..600 {
        xml.push_str("<a><b><c>");
    }
    xml.push_str("]]></root>");
    assert!(xml_nesting_depth_within_limit(&xml, 1));
}

#[test]
fn processing_instructions_and_doctype_are_skipped() {
    let xml = concat!(
        r#"<?xml version="1.0" encoding="UTF-8"?>"#,
        r#"<?target <a><b><c> ?>"#,
        r#"<!DOCTYPE root [<!ENTITY e "x">]>"#,
        "<root><child/></root>"
    );
    // `<child/>` is still an element nested inside `<root>`, so the document
    // is two levels deep: the PI and DOCTYPE contribute nothing, and only the
    // real elements count.
    assert!(xml_nesting_depth_within_limit(xml, 2));
    assert!(!xml_nesting_depth_within_limit(xml, 1));
}

#[test]
fn a_quoted_angle_bracket_does_not_terminate_a_start_tag() {
    // Without quote awareness each tag would terminate at the `>` inside the
    // attribute value and, with `/` as the last significant byte, look
    // self-closing — measuring 300 real levels as depth 1.
    let mut xml = String::new();
    for _ in 0..300 {
        xml.push_str(r#"<n note="/>">"#);
    }
    xml.push_str("leaf");
    for _ in 0..300 {
        xml.push_str("</n>");
    }
    assert!(!xml_nesting_depth_within_limit(&xml, 256));
    assert!(xml_nesting_depth_within_limit(&xml, 300));

    // Single quotes behave identically, and a `>` inside a value is not a
    // self-closing marker on its own.
    assert!(xml_nesting_depth_within_limit(
        r#"<root><n note='a > b'>x</n></root>"#,
        2
    ));
}

#[test]
fn unterminated_constructs_end_the_scan_without_rejecting() {
    // `roxmltree` rejects each of these itself; the screen must not pretend to
    // have measured a depth it could not see.
    assert!(xml_nesting_depth_within_limit("<root><!-- unterminated", 1));
    assert!(xml_nesting_depth_within_limit(
        "<root><![CDATA[ unterminated",
        1
    ));
    assert!(xml_nesting_depth_within_limit("<root><?pi unterminated", 1));
    assert!(xml_nesting_depth_within_limit("<root><!ATTLIST", 1));
    assert!(xml_nesting_depth_within_limit("<root></unterminated", 1));
    assert!(xml_nesting_depth_within_limit("<root><n", 2));
}

#[test]
fn multibyte_text_does_not_shift_the_scan() {
    // Every delimiter inspected is ASCII, so byte indexing cannot split a UTF-8
    // sequence or miscount around one.
    let xml = "<root><n>日本語 — “quoted” 🎉</n><n>é</n></root>";
    assert!(xml_nesting_depth_within_limit(xml, 2));
    assert!(!xml_nesting_depth_within_limit(xml, 1));
}

#[test]
fn a_stray_close_tag_cannot_drive_depth_negative() {
    // `saturating_sub` keeps an unbalanced document from "crediting" depth that
    // a later nesting run could then spend.
    let mut xml = String::from("</a></a></a>");
    xml.push_str(&nested(300));
    assert!(!xml_nesting_depth_within_limit(&xml, 256));
}

#[test]
fn unqualified_attribute_ignores_a_prefixed_look_alike() {
    // roxmltree 0.21 `Node::attribute("ID")` returns the first attribute whose
    // local name is `ID` in any namespace, here the attacker's `x:ID`.
    let xml = r##"<a xmlns:x="urn:x" x:ID="forged" ID="real" x:URI="#forged"/>"##;
    let doc = roxmltree::Document::parse(xml).expect("well-formed");
    let root = doc.root_element();
    assert_eq!(root.unqualified_attribute("ID"), Some("real"));
    assert_eq!(root.unqualified_attribute("URI"), None);
    assert_eq!(root.attribute(("urn:x", "ID")), Some("forged"));
}
