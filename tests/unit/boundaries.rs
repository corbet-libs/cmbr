use super::*;

#[test]
fn error_categories_and_text_validation_never_retain_leaf_details() {
    assert_eq!(Error::from(cnrl::Error::Storage), Error::Unavailable);
    assert_eq!(Error::from(cnrl::Error::Scope), Error::Identity);
    assert_eq!(Error::from(crgs::Error::Storage), Error::Unavailable);
    assert_eq!(Error::from(ckyh::Error::Storage), Error::Unavailable);
    assert_eq!(
        Error::from(cpns::server::Error::Storage),
        Error::Unavailable
    );
    assert_eq!(Error::from(clbs::Error::Storage), Error::Unavailable);
    assert_eq!(Error::from(clbs::Error::Clock), Error::Unavailable);
    assert_eq!(Error::from(clbs::Error::CommunityMismatch), Error::Identity);
    for bad in [
        "".to_owned(),
        " ".into(),
        "private\nsubject".into(),
        "x".repeat(1025),
    ] {
        assert_eq!(text(&bad), Err(Error::InvalidInput));
    }
    assert_eq!(text("valid"), Ok(()));
    for error in [
        Error::InvalidInput,
        Error::Identity,
        Error::Transition,
        Error::Register,
        Error::Passkey,
        Error::Policy,
        Error::Restricted,
        Error::Pin,
        Error::ExtensionsUnavailable,
        Error::Busy,
        Error::Unavailable,
    ] {
        assert!(!error.to_string().contains("private"));
        assert!(!format!("{error:?}").contains("private"));
    }
}
