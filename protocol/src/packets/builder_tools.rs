use std::collections::HashMap;
use macros::{packet_enum, packet_field};
use crate::io::codecs::FixedOption;
use crate::packets::assets::block_type::Rotation;

#[packet_field]
pub struct BuilderToolState {
    pub is_brush: bool,
    pub id: Option<String>,
    pub args: Vec<BuilderToolArg>
}

#[packet_field]
pub struct BuilderToolBrushData {
    pub width: FixedOption<BuilderToolIntArg>,
    pub height: FixedOption<BuilderToolIntArg>,
    pub thickness: FixedOption<BuilderToolIntArg>,
    pub capped: FixedOption<BuilderToolBoolArg>,
    pub shape: FixedOption<BuilderToolBrushShapeArg>,
    pub origin: FixedOption<BuilderToolBrushOriginArg>,
    pub origin_rotation: FixedOption<BuilderToolBoolArg>,
    pub rotation_axis: FixedOption<BuilderToolBrushAxisArg>,
    pub rotation_angle: FixedOption<BuilderToolRotationArg>,
    pub mirror_axis: FixedOption<BuilderToolBrushAxisArg>,
    pub use_mask_commands: FixedOption<BuilderToolBoolArg>,
    pub invert_mask: FixedOption<BuilderToolBoolArg>,
    pub material: Option<BuilderToolBlockArg>,
    pub favorite_materials: Vec<BuilderToolBlockArg>,
    pub mask: Option<BuilderToolMaskArg>,
    pub mask_above: Option<BuilderToolMaskArg>,
    pub mask_not: Option<BuilderToolMaskArg>,
    pub mask_below: Option<BuilderToolMaskArg>,
    pub mask_adjacent: Option<BuilderToolMaskArg>,
    pub mask_neighbor: Option<BuilderToolMaskArg>,
    pub mask_commands: Vec<BuilderToolStringArg>,
}

#[packet_field]
pub struct BuilderToolArg {
    pub required: bool,
    pub arg_type: BuilderToolArgType,
    pub id: Option<String>,
    pub bool_arg: Option<BuilderToolBoolArg>,
    pub float_arg: Option<BuilderToolFloatArg>,
    pub int_arg: Option<BuilderToolIntArg>,
    pub brush_shape_arg: Option<BuilderToolBrushShapeArg>,
    pub brush_origin_arg: Option<BuilderToolBrushOriginArg>,
    pub brush_axis_arg: Option<BuilderToolBrushAxisArg>,
    pub rotation_arg: Option<BuilderToolRotationArg>,
    pub string_arg: Option<BuilderToolStringArg>,
    pub block_arg: Option<BuilderToolBlockArg>,
    pub mask_arg: Option<BuilderToolMaskArg>,
    pub option_arg: Option<BuilderToolOptionArg>,
}

#[packet_field]
pub struct BuilderToolIntArg {
    pub default_value: i32,
    pub min: i32,
    pub max: i32
}

#[packet_field]
pub struct BuilderToolFloatArg {
    pub default_value: f32,
    pub min: f32,
    pub max: f32
}

#[packet_field]
pub struct BuilderToolBoolArg {
    pub default_value: bool
}

#[packet_field]
pub struct BuilderToolBrushShapeArg {
    pub default_value: BrushShape
}

#[packet_enum]
pub enum BrushShape {
    Cube,
    Sphere,
    Cylinder,
    Cone,
    InvertedCone,
    Pyramid,
    InvertedPyramid,
    Dome,
    InvertedDome,
    Diamond,
    Torus
}

#[packet_field]
pub struct BuilderToolBrushOriginArg {
    pub default_value: BrushOrigin
}

#[packet_enum]
pub enum BrushOrigin {
    Center,
    Bottom,
    Top
}

#[packet_field]
pub struct BuilderToolBrushAxisArg {
    pub default_value: BrushAxis,
}

#[packet_enum]
pub enum BrushAxis {
    None,
    Auto,
    X,
    Y,
    Z
}

#[packet_field]
pub struct BuilderToolRotationArg {
    pub default_value: Rotation
}

#[packet_field]
pub struct BuilderToolBlockArg {
    pub allow_pattern: bool,
    pub default_value: Option<String>
}

#[packet_field]
pub struct BuilderToolMaskArg {
    pub default_value: Option<String>
}

#[packet_field]
pub struct BuilderToolStringArg {
    pub default_value: Option<String>
}

#[packet_enum]
pub enum BuilderToolArgType {
    Bool,
    Float,
    Int,
    String,
    Block,
    Mask,
    BrushShape,
    BrushOrigin,
    BrushAxis,
    Rotation,
    Option
}

#[packet_field]
pub struct BuilderToolOptionArg {
    pub default_value: Option<String>,
    pub options: Vec<String>
}