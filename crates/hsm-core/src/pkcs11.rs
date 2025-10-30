//! PKCS#11 metadata support for hsm-core

use crate::models::{KeyMetadata, KeyPurpose, KeyAlgorithm};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// PKCS#11 object class
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Pkcs11ObjectClass {
    Data,
    Certificate,
    PublicKey,
    PrivateKey,
    SecretKey,
    HardwareFeature,
    DomainParameters,
    Mechanism,
    OtpKey,
}

/// PKCS#11 key type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Pkcs11KeyType {
    Rsa,
    Dsa,
    Dh,
    Ec,
    X9_42Dh,
    Kea,
    GenericSecret,
    Rc2,
    Rc4,
    Des,
    Des2,
    Des3,
    Cast,
    Cast3,
    Cast128,
    Rc5,
    Idea,
    Skipjack,
    Baton,
    Juniper,
    Cdmf,
    Aes,
    Blowfish,
    Twofish,
    Securid,
    Hotp,
    Acti,
    Camellia,
    Aria,
}

/// PKCS#11 mechanism type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Pkcs11MechanismType {
    RsaPkcsKeyPairGen,
    RsaPkcs,
    Rsa9796,
    RsaX509,
    Md2RsaPkcs,
    Md5RsaPkcs,
    Sha1RsaPkcs,
    Ripemd128RsaPkcs,
    Ripemd160RsaPkcs,
    RsaPkcsOaep,
    RsaX931KeyPairGen,
    RsaX931,
    Sha1RsaX931,
    RsaPss,
    Sha1RsaPss,
    Sha256RsaPkcs,
    Sha384RsaPkcs,
    Sha512RsaPkcs,
    Sha256RsaPss,
    Sha384RsaPss,
    Sha512RsaPss,
    Rc2KeyGen,
    Rc2Ecb,
    Rc2Cbc,
    Rc2Mac,
    Rc2MacGeneral,
    Rc2CbcPad,
    Rc4KeyGen,
    Rc4,
    DesKeyGen,
    DesEcb,
    DesCbc,
    DesMac,
    DesMacGeneral,
    DesCbcPad,
    Des2KeyGen,
    Des3KeyGen,
    Des3Ecb,
    Des3Cbc,
    Des3Mac,
    Des3MacGeneral,
    Des3CbcPad,
    DesCdmfKeyGen,
    DesCdmf,
    Md2,
    Md2Hmac,
    Md2HmacGeneral,
    Md5,
    Md5Hmac,
    Md5HmacGeneral,
    Sha1,
    Sha1Hmac,
    Sha1HmacGeneral,
    Sha256,
    Sha256Hmac,
    Sha256HmacGeneral,
    Sha384,
    Sha384Hmac,
    Sha384HmacGeneral,
    Sha512,
    Sha512Hmac,
    Sha512HmacGeneral,
    Sha224,
    Sha224Hmac,
    Sha224HmacGeneral,
    SecuridKeyGen,
    Securid,
    HotpKeyGen,
    Hotp,
    Acti,
    ActiKeyGen,
    CamelliaKeyGen,
    CamelliaEcb,
    CamelliaCbc,
    CamelliaMac,
    CamelliaMacGeneral,
    CamelliaCbcPad,
    CamelliaEcbEncryptData,
    CamelliaCbcEncryptData,
    AriaKeyGen,
    AriaEcb,
    AriaCbc,
    AriaMac,
    AriaMacGeneral,
    AriaCbcPad,
    AriaEcbEncryptData,
    AriaCbcEncryptData,
    AesKeyGen,
    AesEcb,
    AesCbc,
    AesMac,
    AesMacGeneral,
    AesCbcPad,
    AesCtr,
    AesGcm,
    AesCcm,
    AesCts,
    AesCmac,
    AesCmacGeneral,
    AesXts,
    AesGcmV1,
    AesCcmV1,
    AesKwp,
    AesKwpV1,
    Des3CbcEncryptData,
    Des3EcbEncryptData,
    AesEcbEncryptData,
    AesCbcEncryptData,
    AesOfb,
    AesCfb1,
    AesCfb8,
    AesCfb128,
    AesCfb64,
    AesCfb32,
    AesCfb16,
    AesCfb24,
    AesCfb40,
    AesCfb48,
    AesCfb56,
    AesGmac,
    AesSiphash128,
    AesSiphash256,
    AesXcbcMac,
    AesXcbcMac96,
    AesGmacV1,
    BlowfishKeyGen,
    BlowfishCbc,
    Ecdsa,
    EcdsaSha1,
    EcdsaSha224,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
    AesCfb1V2,
    AesCfb8V2,
    AesCfb128V2,
    AesCfb64V2,
    AesCfb32V2,
    AesCfb16V2,
    AesCfb24V2,
    AesCfb40V2,
    AesCfb48V2,
    AesCfb56V2,
    VendorDefined,
}

/// PKCS#11 attribute type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Pkcs11AttributeType {
    Class,
    Token,
    Private,
    Label,
    Application,
    Value,
    ObjectId,
    CertType,
    Issuer,
    SerialNumber,
    AcIssuer,
    Owner,
    AttrTypes,
    Trusted,
    CertificateCategory,
    JavaMidpSecurityDomain,
    Url,
    HashOfSubjectPublicKey,
    HashOfIssuerPublicKey,
    CheckValue,
    KeyType,
    Subject,
    Id,
    Sensitive,
    Encrypt,
    Decrypt,
    Wrap,
    Unwrap,
    Sign,
    SignRecover,
    Verify,
    VerifyRecover,
    Derive,
    StartDate,
    EndDate,
    Modulus,
    ModulusBits,
    PublicExponent,
    PrivateExponent,
    Prime1,
    Prime2,
    Exponent1,
    Exponent2,
    Coefficient,
    Prime,
    Subprime,
    Base,
    PrimeBits,
    SubprimeBits,
    ValueBits,
    ValueLen,
    Extractable,
    Local,
    NeverExtractable,
    AlwaysSensitive,
    KeyGenMechanism,
    Modifiable,
    Copyable,
    Destroyable,
    Ecdh1DeriveParams,
    Ecdh1DeriveParamsKdf,
    Ecdh1DeriveParamsSharedData,
    Ecdh1DeriveParamsPublicData,
    Ecdh1DeriveParamsKdfOutput,
    Ecdh1DeriveParamsKdfOutputLen,
    Ecdh1DeriveParamsKdfOutputData,
    Ecdh1DeriveParamsKdfOutputDataLen,
    Ecdh1DeriveParamsKdfOutputDataData,
    Ecdh1DeriveParamsKdfOutputDataDataLen,
    Ecdh1DeriveParamsKdfOutputDataDataData,
    Ecdh1DeriveParamsKdfOutputDataDataDataLen,
    Ecdh1DeriveParamsKdfOutputDataDataDataData,
    Ecdh1DeriveParamsKdfOutputDataDataDataDataLen,
    Ecdh1DeriveParamsKdfOutputDataDataDataDataData,
    Ecdh1DeriveParamsKdfOutputDataDataDataDataDataLen,
    Ecdh1DeriveParamsKdfOutputDataDataDataDataDataData,
    Ecdh1DeriveParamsKdfOutputDataDataDataDataDataDataLen,
    Ecdh1DeriveParamsKdfOutputDataDataDataDataDataDataData,
    Ecdh1DeriveParamsKdfOutputDataDataDataDataDataDataDataLen,
    Ecdh1DeriveParamsKdfOutputDataDataDataDataDataDataDataData,
    Ecdh1DeriveParamsKdfOutputDataDataDataDataDataDataDataDataLen,
    Ecdh1DeriveParamsKdfOutputDataDataDataDataDataDataDataDataData,
    Ecdh1DeriveParamsKdfOutputDataDataDataDataDataDataDataDataDataLen,
    Ecdh1DeriveParamsKdfOutputDataDataDataDataDataDataDataDataDataData,
    Ecdh1DeriveParamsKdfOutputDataDataDataDataDataDataDataDataDataDataLen,
    AllowedMechanisms,
}

/// PKCS#11 metadata for a key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pkcs11Metadata {
    pub object_class: Pkcs11ObjectClass,
    pub key_type: Option<Pkcs11KeyType>,
    pub label: Option<String>,
    pub id: Option<String>,
    pub allowed_mechanisms: Vec<Pkcs11MechanismType>,
    pub attributes: HashMap<Pkcs11AttributeType, Vec<u8>>,
}

impl Pkcs11Metadata {
    /// Create new PKCS#11 metadata
    pub fn new() -> Self {
        Self {
            object_class: Pkcs11ObjectClass::PrivateKey,
            key_type: None,
            label: None,
            id: None,
            allowed_mechanisms: Vec::new(),
            attributes: HashMap::new(),
        }
    }
    
    /// Create PKCS#11 metadata from key metadata
    pub fn from_key_metadata(metadata: &KeyMetadata) -> Self {
        let mut pkcs11_meta = Self::new();
        
        // Set object class based on key usage
        pkcs11_meta.object_class = if metadata.usage.contains(&KeyPurpose::Sign) {
            Pkcs11ObjectClass::PrivateKey
        } else {
            Pkcs11ObjectClass::SecretKey
        };
        
        // Set key type
        pkcs11_meta.key_type = Some(Self::key_algorithm_to_pkcs11_type(metadata.algorithm));
        
        // Set label and id
        pkcs11_meta.label = metadata.description.clone();
        pkcs11_meta.id = Some(metadata.id.clone());
        
        // Set allowed mechanisms based on key usage
        pkcs11_meta.allowed_mechanisms = Self::get_allowed_mechanisms(metadata);
        
        pkcs11_meta
    }
    
    /// Convert KeyAlgorithm to PKCS#11 key type
    fn key_algorithm_to_pkcs11_type(algorithm: crate::models::KeyAlgorithm) -> Pkcs11KeyType {
        use crate::models::KeyAlgorithm;
        use Pkcs11KeyType::*;
        
        match algorithm {
            KeyAlgorithm::Aes256Gcm => Aes,
            KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => Rsa,
            KeyAlgorithm::P256 | KeyAlgorithm::P384 => Ec,
            // Post-quantum and hybrid types would need custom mappings
            _ => GenericSecret,
        }
    }
    
    /// Get allowed mechanisms based on key metadata
    fn get_allowed_mechanisms(metadata: &KeyMetadata) -> Vec<Pkcs11MechanismType> {
        let mut mechanisms = Vec::new();
        
        for purpose in &metadata.usage {
            match purpose {
                KeyPurpose::Encrypt => {
                    mechanisms.push(Pkcs11MechanismType::AesGcm);
                }
                KeyPurpose::Decrypt => {
                    mechanisms.push(Pkcs11MechanismType::AesGcm);
                }
                KeyPurpose::Sign => {
                    match metadata.algorithm {
                        KeyAlgorithm::P256 => mechanisms.push(Pkcs11MechanismType::Ecdsa),
                        KeyAlgorithm::P384 => mechanisms.push(Pkcs11MechanismType::Ecdsa),
                        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => mechanisms.push(Pkcs11MechanismType::RsaPkcs),
                        _ => {}
                    }
                }
                KeyPurpose::Verify => {
                    match metadata.algorithm {
                        KeyAlgorithm::P256 => mechanisms.push(Pkcs11MechanismType::Ecdsa),
                        KeyAlgorithm::P384 => mechanisms.push(Pkcs11MechanismType::Ecdsa),
                        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => mechanisms.push(Pkcs11MechanismType::RsaPkcs),
                        _ => {}
                    }
                }
                KeyPurpose::Wrap => {
                    mechanisms.push(Pkcs11MechanismType::RsaPkcs);
                }
                KeyPurpose::Unwrap => {
                    mechanisms.push(Pkcs11MechanismType::RsaPkcs);
                }
            }
        }
        
        mechanisms
    }
}

impl Default for Pkcs11Metadata {
    fn default() -> Self {
        Self::new()
    }
}