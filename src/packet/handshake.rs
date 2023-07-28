use chacha20poly1305::{AeadCore, AeadInPlace, ChaCha20Poly1305, Nonce};
use digest::{generic_array::GenericArray, typenum::Unsigned};
use x25519_dalek::{EphemeralSecret, PublicKey};

use super::RtpPacketType;

/// Diffie-Hellman verifying key, stored as bytes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, bytemuck::TransparentWrapper, bytemuck::NoUninit,
)]
#[repr(transparent)]
pub struct DhVerifyingKey([u8; 32]);

impl From<x25519_dalek::PublicKey> for DhVerifyingKey {
    fn from(key: x25519_dalek::PublicKey) -> Self {
        Self(key.to_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, bytemuck::NoUninit)]
#[repr(C)]
pub struct VerifyingKeyAead([u8; 32], [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, bytemuck::NoUninit)]
#[repr(C)]
pub struct Tai64NAead([u8; 12], [u8; 16]);

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    bytemuck::TransparentWrapper,
    bytemuck::Pod,
    bytemuck::Zeroable,
)]
#[repr(transparent)]
pub struct SessionId(pub u32);

/// This is pretty much exactly the Wireguard handshake initiation packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, bytemuck::NoUninit)]
#[repr(C)]
pub struct RtpHandshakeInit {
    /// This must always be [RtpPacketType::HandshakeInitiation]
    ty: RtpPacketType,
    _reserved: [u8; 3],
    /// Initiator's ID for the current transmission session (randomly generated when beginning handshake)
    pub initiator_sid: SessionId,
    /// Ephemeral verifying key used for Diffie-Hellman key exchange
    pub initiator_ephemeral: DhVerifyingKey,
    /// Initiator's public key + Poly1305 authentication tag
    pub initiator_key: VerifyingKeyAead,
    /// TAI64 timestamp + Poly1305 authentication tag
    pub timestamp: Tai64NAead,
    _mac1: [u8; 16],
    _mac2: [u8; 16],
}

/// This is pretty much exactly the Wireguard handshake response packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, bytemuck::NoUninit)]
#[repr(C)]
pub struct RtpHandshakeResponse {
    /// This must always be [RtpPacketType::HandshakeResponse]
    ty: RtpPacketType,
    _reserved: [u8; 3],
    /// Responder's ID for the current transmission session (randomly generated when responding to handshake)
    pub responder_sid: SessionId,
    /// Initiator's ID for the current transmission session; read from [RtpHandshakeInit]
    pub initiator_sid: SessionId,
    /// Responder's ephemeral verifying key for Diffie-Hellman key exchange
    pub responder_ephemeral: DhVerifyingKey,
    /// TODO
    pub empty: [u8; 16],
    _mac1: [u8; 16],
    _mac2: [u8; 16],
}

pub const PROTOCOL_NAME: &'static str = "Noise_XX_25519_ChaChaPoly_BLAKE3";
pub const PROTOCOL_ID: &'static str = "RuinTransport SignalGarden ash@ashwalker.net";

pub struct CipherState<Cipher = ChaCha20Poly1305> {
    cipher: Cipher,
    pub counter: u64,
}

impl<Cipher: digest::KeyInit + AeadCore + AeadInPlace> CipherState<Cipher> {
    pub fn initialize_key(&mut self, key: &GenericArray<u8, Cipher::KeySize>) {
        self.cipher = Cipher::new(&key);
    }

    pub fn cipher_nonce(&self) -> GenericArray<u8, Cipher::NonceSize> {
        let mut res = vec![0u8; Cipher::NonceSize::USIZE];
        (&mut res[0..std::mem::size_of::<u64>()]).copy_from_slice(&self.counter.to_le_bytes());
        GenericArray::clone_from_slice(&res)
    }

    pub fn encrypt_with_ad_array<const N: usize>(
        &mut self,
        ad: &[u8],
        plaintext: &[u8; N],
    ) -> Result<[u8; N + Cipher::TagSize::USIZE], chacha20poly1305::Error> {
        let mut res = [0u8; N + Cipher::TagSize::USIZE];
        (&mut res[0..N]).copy_from_slice(plaintext);
        let tag =
            self.cipher
                .encrypt_in_place_detached(&self.cipher_nonce(), ad, &mut res[0..N])?;
        self.counter += 1;
        (&mut res[N..]).copy_from_slice(tag.as_slice());
        Ok(res)
    }
}

pub struct HandshakeInitiator {
    static_local: (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey),
    eph_local: (x25519_dalek::EphemeralSecret, x25519_dalek::PublicKey),
    hash: blake3::Hash,
    chaining_key: [u8; 32],
    enc_key: [u8; 32],
    counter: u64,
}

fn hkdf<const N: usize, const HASH_LEN: usize>(
    key: &[u8; HASH_LEN],
    input: &[u8],
) -> [[u8; HASH_LEN]; N] {
    type Hkdf = hkdf::Hkdf<blake3::Hasher, hkdf::hmac::SimpleHmac<blake3::Hasher>>;
    let mut res = [[0; HASH_LEN]; N];
    let kdf = Hkdf::new(Some(key), input);
    for t in &mut res {
        kdf.expand(&[], t).unwrap();
    }
    res
}

fn aead<const N: usize>(
    key: &chacha20poly1305::Key,
    nonce: &chacha20poly1305::Nonce,
    plain: &[u8; N],
    aad: &[u8],
) -> [u8; N + 16] {
    use chacha20poly1305::{AeadInPlace, KeyInit};
    let mut res = [0u8; N + 16];
    (&mut res[0..N]).copy_from_slice(plain);
    let tag = chacha20poly1305::ChaCha20Poly1305::new(key)
        .encrypt_in_place_detached(nonce, aad, &mut res[0..N])
        .unwrap();
    (&mut res[N..]).copy_from_slice(tag.as_slice());
    res
}

impl HandshakeInitiator {
    pub fn new(
        rng: impl rand::RngCore + rand::CryptoRng,
        local_sign: ed25519_dalek::SigningKey,
        local_ver: ed25519_dalek::VerifyingKey,
        remote_ver: x25519_dalek::PublicKey,
    ) -> Self {
        let chaining_key = blake3::hash(PROTOCOL_NAME.as_bytes());
        let mut hash_res =
            blake3::hash(&[chaining_key.as_bytes(), PROTOCOL_ID.as_bytes()].concat());
        hash_res = blake3::hash(&[hash_res.as_bytes(), remote_ver.as_bytes().as_slice()].concat());

        let eph_sign = EphemeralSecret::random_from_rng(rng);
        let eph_ver = PublicKey::from(&eph_sign);

        let [mut chaining_key] = hkdf::<1, 32>(chaining_key.as_bytes(), eph_ver.as_bytes());
        hash_res = blake3::hash(&[hash_res.as_bytes(), eph_ver.as_bytes().as_slice()].concat());

        // // let eph_secret = eph_sign.diffie_hellman(&remote_ver);
        //
        // let mut temp_key;
        // [chaining_key, temp_key] = hkdf::<2, 32>(&chaining_key, eph_secret.as_bytes());
        //
        // let initiator_key = aead(
        //     &temp_key.into(),
        //     &[0; <ChaCha20Poly1305 as AeadCore>::NonceSize::USIZE].into(),
        //     local_ver.as_bytes(),
        //     hash_res.as_bytes(),
        // );
        //
        // hash_res = blake3::hash(&[hash_res.as_bytes().as_slice(), &initiator_key].concat());
        // let static_secret =
        //     x25519_dalek::x25519(local_sign.to_scalar_bytes(), *remote_ver.as_bytes());
        // [chaining_key, temp_key] = hkdf::<2, 32>(&chaining_key, &static_secret);
        //
        // let timestamp = aead(
        //     &temp_key.into(),
        //     &[0; <ChaCha20Poly1305 as AeadCore>::NonceSize::USIZE].into(),
        //     &tai64::Tai64N::now().to_bytes(),
        //     hash_res.as_bytes(),
        // );
        //
        // hash_res = blake3::hash(&[hash_res.as_bytes().as_slice(), &timestamp].concat());

        Self {
            static_local: (local_sign, local_ver),
            eph_local: (eph_sign, eph_ver),
            hash: hash_res,
            chaining_key,
            enc_key: temp_key,
            counter: 0,
        }
    }
}
