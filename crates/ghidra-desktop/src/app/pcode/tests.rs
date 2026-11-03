use super::*;

fn response(id: u64, generation: u64, address: u64) -> LiftResponse {
    LiftResponse {
        id,
        generation,
        address,
        result: Err("sentinel result".into()),
    }
}

#[test]
fn stale_responses_cannot_replace_another_program_or_selection() {
    let mut state = PcodeState::default();
    let key = state.key(0x1000);
    state.waiting = Some((4, key));
    state.accept(response(3, key.generation, key.address), Some(key.address));
    assert!(state.waiting.is_some());
    state.accept(response(4, key.generation, key.address), Some(0x1001));
    assert!(state.waiting.is_none());
    assert!(state.error.is_none());
    state.waiting = Some((5, key));
    state.clear_for_image();
    state.accept(response(5, key.generation, key.address), Some(key.address));
    assert!(state.error.is_none());
}

#[test]
fn setting_changes_invalidate_only_the_display_not_the_compiler_epoch() {
    let mut state = PcodeState::default();
    let epoch = state.source_epoch;
    let key = state.key(0x1000);
    state.waiting = Some((1, key));
    state.invalidate();
    state.accept(response(1, key.generation, key.address), Some(key.address));
    assert!(state.error.is_none());
    assert_eq!(state.source_epoch, epoch);
    assert_ne!(state.key(0x1000), key);
}

#[test]
fn context_fields_keep_values_and_reject_ambiguous_input() {
    assert_eq!(
        parse_context("longMode=1, addrsize=0x2 opsize=1").unwrap()["addrsize"],
        2
    );
    assert!(parse_context("phase=0 phase=1").is_err());
    assert!(parse_context("phase").is_err());
    assert!(parse_context("=1").is_err());
}
