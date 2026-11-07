use std::sync::RwLock;

use crate::error::{EngineError, EngineResult};
use crate::pubsub::glob_match;
use crate::storage::hashtable::RawHashTable;
use crate::vm::sha256;

// ==================== RFC 2104 HMAC-SHA256 ====================

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        k_block[..32].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }

    let mut inner_input = Vec::with_capacity(64 + message.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(message);
    let inner_digest = sha256(&inner_input);

    let mut outer_input = [0u8; 96];
    outer_input[..64].copy_from_slice(&opad);
    outer_input[64..].copy_from_slice(&inner_digest);
    sha256(&outer_input)
}

#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ==================== RFC 8439 CHACHA20-POLY1305 IETF AEAD ====================

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut initial = [0u32; 16];
    initial[0] = 0x6170_7865;
    initial[1] = 0x3320_646e;
    initial[2] = 0x7962_2d32;
    initial[3] = 0x6b20_6574;

    for i in 0..8 {
        let off = i * 4;
        initial[4 + i] = u32::from_le_bytes([key[off], key[off + 1], key[off + 2], key[off + 3]]);
    }
    initial[12] = counter;
    for i in 0..3 {
        let off = i * 4;
        initial[13 + i] =
            u32::from_le_bytes([nonce[off], nonce[off + 1], nonce[off + 2], nonce[off + 3]]);
    }

    let mut working = initial;
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let sum = working[i].wrapping_add(initial[i]).to_le_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&sum);
    }
    out
}

pub fn chacha20_xor(key: &[u8; 32], initial_counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut counter = initial_counter;
    for chunk in data.chunks_mut(64) {
        let ks = chacha20_block(key, counter, nonce);
        for (i, b) in chunk.iter_mut().enumerate() {
            *b ^= ks[i];
        }
        counter = counter.wrapping_add(1);
    }
}

/// RFC 8439 Section 2.5 Poly1305 MAC over $GF(2^{130} - 5)$ using 5 x 26-bit limbs in safe `u64`/`u128`.
pub fn poly1305_mac(otk: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let t0 = u32::from_le_bytes([otk[0], otk[1], otk[2], otk[3]]) as u64;
    let t1 = u32::from_le_bytes([otk[4], otk[5], otk[6], otk[7]]) as u64;
    let t2 = u32::from_le_bytes([otk[8], otk[9], otk[10], otk[11]]) as u64;
    let t3 = u32::from_le_bytes([otk[12], otk[13], otk[14], otk[15]]) as u64;

    // Clamp r per RFC 8439 Section 2.5
    let r0 = t0 & 0x03ff_ffff;
    let r1 = ((t0 >> 26) | (t1 << 6)) & 0x03ff_ff03;
    let r2 = ((t1 >> 20) | (t2 << 12)) & 0x03ff_c0ff;
    let r3 = ((t2 >> 14) | (t3 << 18)) & 0x03f0_3fff;
    let r4 = (t3 >> 8) & 0x000f_ffff;

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let mut h0 = 0u64;
    let mut h1 = 0u64;
    let mut h2 = 0u64;
    let mut h3 = 0u64;
    let mut h4 = 0u64;

    for chunk in msg.chunks(16) {
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1;
        let hibit = if chunk.len() == 16 { 1u64 << 24 } else { 0u64 };

        let m0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as u64;
        let m1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]) as u64;
        let m2 = u32::from_le_bytes([block[8], block[9], block[10], block[11]]) as u64;
        let m3 = u32::from_le_bytes([block[12], block[13], block[14], block[15]]) as u64;

        h0 += m0 & 0x03ff_ffff;
        h1 += ((m0 >> 26) | (m1 << 6)) & 0x03ff_ffff;
        h2 += ((m1 >> 20) | (m2 << 12)) & 0x03ff_ffff;
        h3 += ((m2 >> 14) | (m3 << 18)) & 0x03ff_ffff;
        h4 += (m3 >> 8) | hibit;

        let d0 = (h0 as u128) * (r0 as u128)
            + (h1 as u128) * (s4 as u128)
            + (h2 as u128) * (s3 as u128)
            + (h3 as u128) * (s2 as u128)
            + (h4 as u128) * (s1 as u128);
        let mut d1 = (h0 as u128) * (r1 as u128)
            + (h1 as u128) * (r0 as u128)
            + (h2 as u128) * (s4 as u128)
            + (h3 as u128) * (s3 as u128)
            + (h4 as u128) * (s2 as u128);
        let mut d2 = (h0 as u128) * (r2 as u128)
            + (h1 as u128) * (r1 as u128)
            + (h2 as u128) * (r0 as u128)
            + (h3 as u128) * (s4 as u128)
            + (h4 as u128) * (s3 as u128);
        let mut d3 = (h0 as u128) * (r3 as u128)
            + (h1 as u128) * (r2 as u128)
            + (h2 as u128) * (r1 as u128)
            + (h3 as u128) * (r0 as u128)
            + (h4 as u128) * (s4 as u128);
        let mut d4 = (h0 as u128) * (r4 as u128)
            + (h1 as u128) * (r3 as u128)
            + (h2 as u128) * (r2 as u128)
            + (h3 as u128) * (r1 as u128)
            + (h4 as u128) * (r0 as u128);

        let mut c = (d0 >> 26) as u64;
        h0 = (d0 as u64) & 0x03ff_ffff;
        d1 += c as u128;
        c = (d1 >> 26) as u64;
        h1 = (d1 as u64) & 0x03ff_ffff;
        d2 += c as u128;
        c = (d2 >> 26) as u64;
        h2 = (d2 as u64) & 0x03ff_ffff;
        d3 += c as u128;
        c = (d3 >> 26) as u64;
        h3 = (d3 as u64) & 0x03ff_ffff;
        d4 += c as u128;
        c = (d4 >> 26) as u64;
        h4 = (d4 as u64) & 0x03ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c;
    }

    // Complete modular reduction mod 2^130 - 5
    let mut c = h1 >> 26;
    h1 &= 0x03ff_ffff;
    h2 += c;
    c = h2 >> 26;
    h2 &= 0x03ff_ffff;
    h3 += c;
    c = h3 >> 26;
    h3 &= 0x03ff_ffff;
    h4 += c;
    c = h4 >> 26;
    h4 &= 0x03ff_ffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x03ff_ffff;
    h1 += c;

    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x03ff_ffff;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x03ff_ffff;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x03ff_ffff;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x03ff_ffff;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g4 >> 63).wrapping_sub(1);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    let inv = !mask;
    h0 = (h0 & inv) | g0;
    h1 = (h1 & inv) | g1;
    h2 = (h2 & inv) | g2;
    h3 = (h3 & inv) | g3;
    h4 = (h4 & inv) | (g4 & mask);

    let f0 = (h0 | (h1 << 26)) & 0xffff_ffff;
    let f1 = ((h1 >> 6) | (h2 << 20)) & 0xffff_ffff;
    let f2 = ((h2 >> 12) | (h3 << 14)) & 0xffff_ffff;
    let f3 = ((h3 >> 18) | (h4 << 8)) & 0xffff_ffff;

    let pad0 = u32::from_le_bytes([otk[16], otk[17], otk[18], otk[19]]) as u64;
    let pad1 = u32::from_le_bytes([otk[20], otk[21], otk[22], otk[23]]) as u64;
    let pad2 = u32::from_le_bytes([otk[24], otk[25], otk[26], otk[27]]) as u64;
    let pad3 = u32::from_le_bytes([otk[28], otk[29], otk[30], otk[31]]) as u64;

    let mut acc = f0 + pad0;
    let w0 = acc as u32;
    acc = (acc >> 32) + f1 + pad1;
    let w1 = acc as u32;
    acc = (acc >> 32) + f2 + pad2;
    let w2 = acc as u32;
    acc = (acc >> 32) + f3 + pad3;
    let w3 = acc as u32;

    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&w0.to_le_bytes());
    tag[4..8].copy_from_slice(&w1.to_le_bytes());
    tag[8..12].copy_from_slice(&w2.to_le_bytes());
    tag[12..16].copy_from_slice(&w3.to_le_bytes());
    tag
}

fn build_poly1305_aead_input(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let pad16 = |len: usize| -> usize { (16 - (len % 16)) % 16 };
    let mut mac_data =
        Vec::with_capacity(aad.len() + pad16(aad.len()) + ciphertext.len() + pad16(ciphertext.len()) + 16);
    mac_data.extend_from_slice(aad);
    mac_data.resize(mac_data.len() + pad16(aad.len()), 0u8);
    mac_data.extend_from_slice(ciphertext);
    mac_data.resize(mac_data.len() + pad16(ciphertext.len()), 0u8);
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    mac_data
}

/// RFC 8439 Section 2.8 ChaCha20-Poly1305 AEAD Encryption (`ciphertext || 16-byte tag`).
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    let mut out = Vec::with_capacity(plaintext.len() + 16);
    out.extend_from_slice(plaintext);
    chacha20_xor(key, 1, nonce, &mut out);

    let mac_input = build_poly1305_aead_input(aad, &out);
    let tag = poly1305_mac(&otk, &mac_input);
    out.extend_from_slice(&tag);
    out
}

/// RFC 8439 Section 2.8 ChaCha20-Poly1305 AEAD Decryption with constant-time Poly1305 verification.
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> EngineResult<Vec<u8>> {
    if ciphertext_and_tag.len() < 16 {
        return Err(EngineError::CorruptedPersistence(
            "AEAD ciphertext shorter than 16-byte Poly1305 tag".to_string(),
        ));
    }
    let split = ciphertext_and_tag.len() - 16;
    let ciphertext = &ciphertext_and_tag[..split];
    let provided_tag = &ciphertext_and_tag[split..];

    let block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    let mac_input = build_poly1305_aead_input(aad, ciphertext);
    let expected_tag = poly1305_mac(&otk, &mac_input);
    if !constant_time_eq(provided_tag, &expected_tag) {
        return Err(EngineError::CorruptedPersistence(
            "ChaCha20-Poly1305 authentication tag mismatch".to_string(),
        ));
    }

    let mut plaintext = ciphertext.to_vec();
    chacha20_xor(key, 1, nonce, &mut plaintext);
    Ok(plaintext)
}

// ==================== MULTI-USER RBAC ACL ENGINE ====================

pub const PERM_READ: u32 = 1 << 0;
pub const PERM_WRITE: u32 = 1 << 1;
pub const PERM_ADMIN: u32 = 1 << 2;
pub const PERM_PUBSUB: u32 = 1 << 3;
pub const PERM_SCRIPT: u32 = 1 << 4;
pub const PERM_ALL: u32 = PERM_READ | PERM_WRITE | PERM_ADMIN | PERM_PUBSUB | PERM_SCRIPT;

#[derive(Clone, Debug)]
pub struct AclUser {
    pub username: String,
    pub enabled: bool,
    pub nopass: bool,
    pub password_hmac: Option<[u8; 32]>,
    pub permissions: u32,
    pub key_patterns: Vec<Box<[u8]>>,
}

impl AclUser {
    pub fn default_open_user() -> Self {
        Self {
            username: "default".to_string(),
            enabled: true,
            nopass: true,
            password_hmac: None,
            permissions: PERM_ALL,
            key_patterns: vec![b"*".to_vec().into_boxed_slice()],
        }
    }

    fn hash_password(username: &str, password: &[u8]) -> [u8; 32] {
        hmac_sha256(username.as_bytes(), password)
    }

    pub fn verify_password(&self, password: &[u8]) -> bool {
        if !self.enabled {
            return false;
        }
        if self.nopass {
            return true;
        }
        match self.password_hmac {
            Some(ref expected) => {
                let actual = Self::hash_password(&self.username, password);
                constant_time_eq(expected, &actual)
            }
            None => false,
        }
    }

    pub fn allows_key(&self, key: &[u8]) -> bool {
        if self.key_patterns.is_empty() {
            return false;
        }
        self.key_patterns.iter().any(|pat| glob_match(pat, key))
    }
}

pub struct AclManager {
    users: RwLock<RawHashTable<AclUser>>,
}

impl Default for AclManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AclManager {
    pub fn new() -> Self {
        let mut table = RawHashTable::new();
        table.insert(
            b"default".to_vec().into_boxed_slice(),
            AclUser::default_open_user(),
        );
        Self {
            users: RwLock::new(table),
        }
    }

    pub fn requires_initial_auth(&self) -> EngineResult<bool> {
        let guard = self
            .users
            .read()
            .map_err(|_| EngineError::LockPoisoned("ACL read lock"))?;
        Ok(match guard.get(b"default") {
            Some(u) => !u.enabled || !u.nopass,
            None => true,
        })
    }

    pub fn authenticate(&self, username: &[u8], password: &[u8]) -> EngineResult<String> {
        let guard = self
            .users
            .read()
            .map_err(|_| EngineError::LockPoisoned("ACL read lock"))?;
        let Some(user) = guard.get(username) else {
            return Err(EngineError::InvalidArgument(
                "WRONGPASS invalid username-password pair or user is disabled.".to_string(),
            ));
        };
        if !user.verify_password(password) {
            return Err(EngineError::InvalidArgument(
                "WRONGPASS invalid username-password pair or user is disabled.".to_string(),
            ));
        }
        Ok(user.username.clone())
    }

    pub fn set_user(&self, username: &[u8], rules: &[&[u8]]) -> EngineResult<()> {
        let uname = std::str::from_utf8(username)?.to_string();
        let mut guard = self
            .users
            .write()
            .map_err(|_| EngineError::LockPoisoned("ACL write lock"))?;

        let mut user = guard.get(username).cloned().unwrap_or(AclUser {
            username: uname.clone(),
            enabled: false,
            nopass: false,
            password_hmac: None,
            permissions: 0,
            key_patterns: Vec::new(),
        });

        for &rule in rules {
            if rule.eq_ignore_ascii_case(b"on") {
                user.enabled = true;
            } else if rule.eq_ignore_ascii_case(b"off") {
                user.enabled = false;
            } else if rule.eq_ignore_ascii_case(b"nopass") {
                user.nopass = true;
                user.password_hmac = None;
            } else if rule.eq_ignore_ascii_case(b"resetkeys") {
                user.key_patterns.clear();
            } else if rule.eq_ignore_ascii_case(b"allkeys") || rule == b"~*" {
                user.key_patterns.push(b"*".to_vec().into_boxed_slice());
            } else if rule.starts_with(b">") {
                user.nopass = false;
                user.password_hmac = Some(AclUser::hash_password(&uname, &rule[1..]));
            } else if rule.starts_with(b"~") {
                user.key_patterns
                    .push(rule[1..].to_vec().into_boxed_slice());
            } else if rule.eq_ignore_ascii_case(b"+@all") || rule.eq_ignore_ascii_case(b"+all") {
                user.permissions = PERM_ALL;
            } else if rule.eq_ignore_ascii_case(b"-@all") || rule.eq_ignore_ascii_case(b"-all") {
                user.permissions = 0;
            } else if rule.eq_ignore_ascii_case(b"+@read") || rule.eq_ignore_ascii_case(b"+read") {
                user.permissions |= PERM_READ;
            } else if rule.eq_ignore_ascii_case(b"-@read") || rule.eq_ignore_ascii_case(b"-read") {
                user.permissions &= !PERM_READ;
            } else if rule.eq_ignore_ascii_case(b"+@write") || rule.eq_ignore_ascii_case(b"+write")
            {
                user.permissions |= PERM_WRITE;
            } else if rule.eq_ignore_ascii_case(b"-@write") || rule.eq_ignore_ascii_case(b"-write")
            {
                user.permissions &= !PERM_WRITE;
            } else if rule.eq_ignore_ascii_case(b"+@admin") || rule.eq_ignore_ascii_case(b"+admin")
            {
                user.permissions |= PERM_ADMIN;
            } else if rule.eq_ignore_ascii_case(b"-@admin") || rule.eq_ignore_ascii_case(b"-admin")
            {
                user.permissions &= !PERM_ADMIN;
            } else if rule.eq_ignore_ascii_case(b"+@pubsub")
                || rule.eq_ignore_ascii_case(b"+pubsub")
            {
                user.permissions |= PERM_PUBSUB;
            } else if rule.eq_ignore_ascii_case(b"+@scripting")
                || rule.eq_ignore_ascii_case(b"+script")
            {
                user.permissions |= PERM_SCRIPT;
            } else {
                return Err(EngineError::InvalidArgument(format!(
                    "Unknown ACL rule '{}'",
                    String::from_utf8_lossy(rule)
                )));
            }
        }

        guard.insert(username.to_vec().into_boxed_slice(), user);
        Ok(())
    }

    pub fn authorize_command(
        &self,
        username: Option<&str>,
        cmd: &[u8],
        first_key: Option<&[u8]>,
    ) -> EngineResult<()> {
        if cmd.eq_ignore_ascii_case(b"AUTH")
            || cmd.eq_ignore_ascii_case(b"HELLO")
            || cmd.eq_ignore_ascii_case(b"QUIT")
        {
            return Ok(());
        }
        let Some(uname) = username else {
            return Err(EngineError::InvalidArgument(
                "NOAUTH Authentication required.".to_string(),
            ));
        };

        let guard = self
            .users
            .read()
            .map_err(|_| EngineError::LockPoisoned("ACL read lock"))?;
        let Some(user) = guard.get(uname.as_bytes()) else {
            return Err(EngineError::InvalidArgument(
                "NOPERM user no longer exists".to_string(),
            ));
        };
        if !user.enabled {
            return Err(EngineError::InvalidArgument(
                "NOPERM user is disabled".to_string(),
            ));
        }

        // Fast path for unmodified default open user
        if user.permissions == PERM_ALL
            && user.key_patterns.len() == 1
            && user.key_patterns[0].as_ref() == b"*"
        {
            return Ok(());
        }

        let required = classify_command_perm(cmd);
        if (user.permissions & required) != required {
            return Err(EngineError::InvalidArgument(format!(
                "NOPERM this user has no permissions to run the '{}' command",
                String::from_utf8_lossy(cmd)
            )));
        }

        if let Some(k) = first_key {
            if !user.allows_key(k) {
                return Err(EngineError::InvalidArgument(
                    "NOPERM this user has no permissions to access one of the keys used as arguments"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn list_users(&self) -> EngineResult<Vec<String>> {
        let guard = self
            .users
            .read()
            .map_err(|_| EngineError::LockPoisoned("ACL read lock"))?;
        let mut out = Vec::with_capacity(guard.len());
        for (_, u) in guard.iter() {
            out.push(format!(
                "user {} {} perms=0x{:02x} keys={}",
                u.username,
                if u.enabled { "on" } else { "off" },
                u.permissions,
                u.key_patterns.len()
            ));
        }
        out.sort();
        Ok(out)
    }
}

pub fn classify_command_perm(cmd: &[u8]) -> u32 {
    if cmd.eq_ignore_ascii_case(b"FLUSHDB")
        || cmd.eq_ignore_ascii_case(b"SAVE")
        || cmd.eq_ignore_ascii_case(b"BGREWRITEAOF")
        || cmd.eq_ignore_ascii_case(b"ACL")
        || cmd.eq_ignore_ascii_case(b"CONFIG")
        || cmd.eq_ignore_ascii_case(b"SLOWLOG")
        || cmd.eq_ignore_ascii_case(b"LSM.COMPACT")
        || cmd.eq_ignore_ascii_case(b"LSM.FLUSH")
        || cmd.starts_with(b"RAFT.")
        || cmd.eq_ignore_ascii_case(b"CLUSTER")
    {
        PERM_ADMIN
    } else if cmd.eq_ignore_ascii_case(b"SUBSCRIBE")
        || cmd.eq_ignore_ascii_case(b"UNSUBSCRIBE")
        || cmd.eq_ignore_ascii_case(b"PSUBSCRIBE")
        || cmd.eq_ignore_ascii_case(b"PUNSUBSCRIBE")
        || cmd.eq_ignore_ascii_case(b"PUBLISH")
        || cmd.eq_ignore_ascii_case(b"PUBSUB")
    {
        PERM_PUBSUB
    } else if cmd.eq_ignore_ascii_case(b"EVAL")
        || cmd.eq_ignore_ascii_case(b"EVALSHA")
        || cmd.eq_ignore_ascii_case(b"SCRIPT")
    {
        PERM_SCRIPT
    } else if cmd.eq_ignore_ascii_case(b"GET")
        || cmd.eq_ignore_ascii_case(b"EXISTS")
        || cmd.eq_ignore_ascii_case(b"TYPE")
        || cmd.eq_ignore_ascii_case(b"STRLEN")
        || cmd.eq_ignore_ascii_case(b"TTL")
        || cmd.eq_ignore_ascii_case(b"PTTL")
        || cmd.eq_ignore_ascii_case(b"DBSIZE")
        || cmd.eq_ignore_ascii_case(b"KEYS")
        || cmd.eq_ignore_ascii_case(b"PING")
        || cmd.eq_ignore_ascii_case(b"ECHO")
        || cmd.eq_ignore_ascii_case(b"INFO")
        || cmd.eq_ignore_ascii_case(b"LLEN")
        || cmd.eq_ignore_ascii_case(b"LINDEX")
        || cmd.eq_ignore_ascii_case(b"LRANGE")
        || cmd.eq_ignore_ascii_case(b"HGET")
        || cmd.eq_ignore_ascii_case(b"HLEN")
        || cmd.eq_ignore_ascii_case(b"HGETALL")
        || cmd.eq_ignore_ascii_case(b"ZSCORE")
        || cmd.eq_ignore_ascii_case(b"ZCARD")
        || cmd.eq_ignore_ascii_case(b"ZRANK")
        || cmd.eq_ignore_ascii_case(b"ZRANGE")
        || cmd.eq_ignore_ascii_case(b"ZRANGEBYSCORE")
        || cmd.eq_ignore_ascii_case(b"GEOPOS")
        || cmd.eq_ignore_ascii_case(b"GEODIST")
        || cmd.eq_ignore_ascii_case(b"GEORADIUS")
        || cmd.eq_ignore_ascii_case(b"XLEN")
        || cmd.eq_ignore_ascii_case(b"XRANGE")
        || cmd.eq_ignore_ascii_case(b"XREAD")
        || cmd.eq_ignore_ascii_case(b"PFCOUNT")
        || cmd.eq_ignore_ascii_case(b"BF.EXISTS")
        || cmd.eq_ignore_ascii_case(b"CMS.QUERY")
        || cmd.eq_ignore_ascii_case(b"VSEARCH")
        || cmd.eq_ignore_ascii_case(b"VCARD")
        || cmd.eq_ignore_ascii_case(b"FT.SEARCH")
        || cmd.eq_ignore_ascii_case(b"FT.SUGG")
        || cmd.eq_ignore_ascii_case(b"TS.GET")
        || cmd.eq_ignore_ascii_case(b"TS.RANGE")
        || cmd.eq_ignore_ascii_case(b"LSM.GET")
        || cmd.eq_ignore_ascii_case(b"LSM.SCAN")
        || cmd.eq_ignore_ascii_case(b"LSM.STATS")
    {
        PERM_READ
    } else {
        PERM_WRITE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc8439_chacha20_poly1305_aead_and_rbac_acl() -> EngineResult<()> {
        // Official RFC 8439 Section 2.8.2 Test Vector
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let sealed = chacha20_poly1305_encrypt(&key, &nonce, &aad, plaintext);
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];
        assert_eq!(&sealed[plaintext.len()..], &expected_tag);

        let opened = chacha20_poly1305_decrypt(&key, &nonce, &aad, &sealed)?;
        assert_eq!(opened.as_slice(), plaintext.as_slice());

        // Flip 1 bit -> Poly1305 MAC MUST reject!
        let mut tampered = sealed.clone();
        tampered[5] ^= 0x01;
        assert!(chacha20_poly1305_decrypt(&key, &nonce, &aad, &tampered).is_err());

        // RBAC ACL enforcement
        let acl = AclManager::new();
        acl.set_user(
            b"reader",
            &[b"on", b">s3cret", b"+read", b"-write", b"~tenantA:*"],
        )?;
        assert_eq!(acl.authenticate(b"reader", b"s3cret")?, "reader");
        assert!(acl.authenticate(b"reader", b"wrong").is_err());

        acl.authorize_command(Some("reader"), b"GET", Some(b"tenantA:item1"))?;
        assert!(acl
            .authorize_command(Some("reader"), b"SET", Some(b"tenantA:item1"))
            .is_err());
        assert!(acl
            .authorize_command(Some("reader"), b"GET", Some(b"tenantB:item1"))
            .is_err());
        Ok(())
    }
}
