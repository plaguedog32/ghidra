use jstd::registry::Registry;
use pcode_types::{
    PCodeOpId, Register, RegisterId, SPACE_CONST, Space, SpaceId, SpaceStore, SpaceType,
};

struct Spaces(Registry<SpaceId, Space>);

impl SpaceStore for Spaces {
    fn spaces(&self) -> &Registry<SpaceId, Space> {
        &self.0
    }
}

#[test]
fn identifiers_implement_the_expected_traits() {
    let register = RegisterId::new(3);
    let operation = PCodeOpId::new(7);
    let space = SpaceId::new(2);

    assert_eq!(usize::from(register), 3);
    assert_eq!(usize::from(operation), 7);
    assert_eq!(usize::from(SPACE_CONST), 0);
    assert_eq!(RegisterId::default(), RegisterId::new(0));
    assert_eq!(register.clone(), register);
    assert!(RegisterId::new(2) < register);
    assert_eq!(format!("{operation}"), "7");

    let bytes = bincode::serde::encode_to_vec(space, bincode::config::standard()).unwrap();
    let (decoded, _): (SpaceId, _) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
    assert_eq!(decoded, space);
}

#[test]
fn spaces_can_be_created_and_resolved() {
    let mut spaces = Spaces(Registry::default());
    let ram = spaces.0.push(Space::new(Some("ram"), 1, 8));

    let resolved = Space::from_id(&spaces, ram);
    assert_eq!(resolved.id, ram);
    assert_eq!(resolved.name.as_deref(), Some("ram"));
    assert_eq!(resolved.word_size, 1);
    assert_eq!(resolved.addr_size, 8);
    assert!(matches!(resolved.ty, SpaceType::Ram));
    assert_eq!(resolved.to_string(), "ram");
    assert_eq!(Space::new(None, 2, 4).to_string(), "space");
}

#[test]
fn register_fields_describe_a_space_slice() {
    let register = Register {
        name: "rax".into(),
        space: SpaceId::new(1),
        offset: 0,
        size: 8,
    };

    assert_eq!(&*register.name, "rax");
    assert_eq!(usize::from(register.space), 1);
    assert_eq!(register.offset, 0);
    assert_eq!(register.size, 8);
}
