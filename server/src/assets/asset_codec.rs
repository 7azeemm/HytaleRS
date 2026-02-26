pub struct BuilderField {
    pub codec: KeyCodec<>
}

pub struct KeyCodec {
    pub key: String,
    pub codec: Codec,
    pub required: bool
}

impl KeyCodec {
    pub fn new(key: String, codec: Codec, required: bool) -> Self {
        if key.is_empty() {
            panic!("Codec Key must not be empty!")
        } else if key.chars().next().unwrap().is_lowercase() {
            panic!("Codec key must start with an uppercase character")
        }

        Self { key, codec, required }
    }
}

pub struct Codec {

}