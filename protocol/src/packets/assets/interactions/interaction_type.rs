use macros::packet_enum;

#[derive(Hash, Eq, PartialEq)]
#[packet_enum]
pub enum InteractionType {
    Primary,
    Secondary,
    Ability1,
    Ability2,
    Ability3,
    Use,
    Pick,
    Pickup,
    CollisionEnter,
    CollisionLeave,
    Collision,
    EntityStatEffect,
    SwapTo,
    SwapFrom,
    Death,
    Wielding,
    ProjectileSpawn,
    ProjectileHit,
    ProjectileMiss,
    ProjectileBounce,
    Held,
    HeldOffhand,
    Equipped,
    Dodge,
    GameModeSwap
}