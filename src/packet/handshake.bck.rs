use snow::HandshakeState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, std::marker::ConstParamTy)]
#[repr(u8)]
pub enum XXInitiatorState {
    PreSend,
    SentEphemeral,
    ReceivedStatic,
}

pub struct XXInitiator<const STATE: XXInitiatorState>(HandshakeState);

impl XXInitiator<{ XXInitiatorState::PreSend }> {
    pub fn new(local_sign: &ed25519_dalek::SigningKey) -> Self {
        Self(
            snow::Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
                .local_private_key(&local_sign.to_bytes())
                .build_initiator()
                .unwrap(),
        )
    }

    pub fn send_ephemeral(self) -> (XXInitiator<{ XXInitiatorState::SentEphemeral }>, Vec<u8>) {
        todo!()
    }
}

impl XXInitiator<{ XXInitiatorState::SentEphemeral }> {
    pub fn recv_static(self) -> XXInitiator<{ XXInitiatorState::ReceivedStatic }> {
        todo!()
    }
}

impl XXInitiator<{ XXInitiatorState::ReceivedStatic }> {
    pub fn send_static(self) -> () {
        todo!()
    }
}
