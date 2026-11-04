//! Hand-written source graphs for native datatype tests. Expected native
//! values in the tests are derived from type.cc/modelrules.cc, not from here.
#![allow(dead_code)]

use std::sync::Arc;

use ghidra_abi::{NativeAlignmentMap, NativeTypeGraph, NativeTypeId};
use ghidra_languages::{DataOrganization, DatatypeClass, DatatypeFilter, MetaType, SizeAlignment};
use ghidra_types::{
    Composite, Endianness, Field, MinimumAlignment, Packing, ResolvedDataOrganization,
    TypeDefinition, TypeId, TypeKind, TypeLayouts,
};

#[derive(Default, Clone)]
pub struct Source {
    pub defs: Vec<TypeDefinition>,
}

impl Source {
    pub fn add(&mut self, kind: TypeKind) -> TypeId {
        self.defs
            .push(TypeDefinition::new(format!("t{}", self.defs.len()), kind));
        TypeId(self.defs.len() - 1)
    }
    pub fn int(&mut self, bytes: u32, signed: bool) -> TypeId {
        self.add(TypeKind::Integer { bytes, signed })
    }
    pub fn float(&mut self, bytes: u32) -> TypeId {
        self.add(TypeKind::Float { bytes })
    }
    pub fn alias(&mut self, target: TypeId) -> TypeId {
        self.add(TypeKind::Alias(target))
    }
    pub fn array(&mut self, element: TypeId, count: u64) -> TypeId {
        self.add(TypeKind::Array { element, count })
    }
    pub fn opaque(&mut self, bytes: u32) -> TypeId {
        self.add(TypeKind::Opaque { bytes })
    }
    pub fn structure(&mut self, fields: &[TypeId]) -> TypeId {
        self.composite(fields, Packing::Default, MinimumAlignment::Default, false)
    }
    pub fn packed(&mut self, fields: &[TypeId]) -> TypeId {
        self.composite(
            fields,
            Packing::Explicit(1),
            MinimumAlignment::Default,
            false,
        )
    }
    pub fn union(&mut self, fields: &[TypeId]) -> TypeId {
        self.composite(fields, Packing::Default, MinimumAlignment::Default, true)
    }
    pub fn composite(
        &mut self,
        fields: &[TypeId],
        packing: Packing,
        minimum_alignment: MinimumAlignment,
        union: bool,
    ) -> TypeId {
        let fields = fields
            .iter()
            .enumerate()
            .map(|(i, ty)| Field::new(format!("f{i}"), *ty))
            .collect();
        self.with_fields(fields, packing, minimum_alignment, union)
    }
    pub fn with_fields(
        &mut self,
        fields: Vec<Field>,
        packing: Packing,
        minimum_alignment: MinimumAlignment,
        union: bool,
    ) -> TypeId {
        let composite = Composite {
            fields,
            packing,
            minimum_alignment,
        };
        self.add(if union {
            TypeKind::Union(composite)
        } else {
            TypeKind::Structure(composite)
        })
    }
    pub fn layouts(&self) -> Arc<TypeLayouts> {
        self.layouts_with(organization(), Endianness::Little)
    }
    pub fn layouts_with(
        &self,
        organization: ResolvedDataOrganization,
        endianness: Endianness,
    ) -> Arc<TypeLayouts> {
        Arc::new(
            TypeLayouts::new_with_endianness(
                self.defs.clone().into(),
                organization,
                endianness,
                Default::default(),
            )
            .unwrap(),
        )
    }
    /// The Java bridge: the resolved organization map is sent to the decoder.
    pub fn native(&self) -> Arc<NativeTypeGraph> {
        let layouts = self.layouts();
        bridge(layouts)
    }
    pub fn native_with_map(&self, map: &[(u32, u32)]) -> Arc<NativeTypeGraph> {
        Arc::new(
            NativeTypeGraph::new(
                self.layouts(),
                &declared_map(map),
                Default::default(),
                Default::default(),
            )
            .unwrap(),
        )
    }
}

pub fn organization() -> ResolvedDataOrganization {
    DataOrganization::default().resolve(8)
}

pub fn bridge(layouts: Arc<TypeLayouts>) -> Arc<NativeTypeGraph> {
    let map =
        NativeAlignmentMap::from_organization(layouts.organization(), Default::default()).unwrap();
    Arc::new(NativeTypeGraph::new(layouts, &map, Default::default(), Default::default()).unwrap())
}

pub fn declared_map(entries: &[(u32, u32)]) -> NativeAlignmentMap {
    let entries: Vec<_> = entries
        .iter()
        .map(|&(size, alignment)| SizeAlignment { size, alignment })
        .collect();
    NativeAlignmentMap::new(Some(&entries), Default::default()).unwrap()
}

pub fn id(ty: TypeId) -> NativeTypeId {
    NativeTypeId(ty.0)
}

pub fn filter(class: DatatypeClass) -> DatatypeFilter {
    DatatypeFilter {
        class,
        min_size: None,
        max_size: None,
        sizes: vec![],
        max_primitives: None,
        min_elements: None,
        max_elements: None,
    }
}

pub fn meta(meta: MetaType) -> DatatypeFilter {
    filter(DatatypeClass::Meta(meta))
}

pub fn hfa() -> DatatypeFilter {
    filter(DatatypeClass::HomogeneousFloatAggregate)
}
