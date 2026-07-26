use hswe_implementation::{error::HsweError, tag::Tag};

#[test]
fn epoch_tag_round_trips_through_canonical_bytes() {
    let tag = Tag::epoch("hswe.example", 42).expect("tag must be valid");

    let bytes = tag.to_canonical_bytes();
    let recovered = Tag::from_canonical_bytes(&bytes).expect("tag bytes must parse");

    assert_eq!(tag, recovered);
    assert_eq!(recovered.application_domain(), "hswe.example");
    assert_eq!(recovered.epoch_number(), 42);
}

#[test]
fn distinct_epoch_tags_have_distinct_canonical_bytes() {
    let first = Tag::epoch("hswe.example", 42).expect("tag must be valid");
    let second = Tag::epoch("hswe.example", 43).expect("tag must be valid");
    let other_domain = Tag::epoch("other.example", 42).expect("tag must be valid");

    assert_ne!(first.to_canonical_bytes(), second.to_canonical_bytes());
    assert_ne!(
        first.to_canonical_bytes(),
        other_domain.to_canonical_bytes()
    );
}

#[test]
fn malformed_tag_bytes_are_rejected() {
    assert_eq!(
        Tag::from_canonical_bytes(&[1, 1, 0]),
        Err(HsweError::InvalidTagEncoding)
    );

    assert_eq!(
        Tag::from_canonical_bytes(&[2, 1, 1, b'a', 0, 0, 0, 0, 0, 0, 0, 1]),
        Err(HsweError::InvalidTagEncoding)
    );

    assert_eq!(
        Tag::from_canonical_bytes(&[1, 2, 1, b'a', 0, 0, 0, 0, 0, 0, 0, 1]),
        Err(HsweError::UnsupportedTagKind)
    );
}

#[test]
fn empty_or_oversized_domains_are_rejected() {
    assert_eq!(Tag::epoch("", 1), Err(HsweError::InputTooLarge));

    let oversized = "a".repeat(256);
    assert_eq!(Tag::epoch(oversized, 1), Err(HsweError::InputTooLarge));
}
