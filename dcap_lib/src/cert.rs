use super::*;

use std::time::*;
use rand_core::OsRng;

use bit_vec::BitVec;
use yasna::models::ObjectIdentifier;
use chrono::Duration;
use chrono::TimeZone;
use chrono::Utc as TzUtc;

use curv::elliptic::curves::p256::{Secp256r1Point, Secp256r1Scalar, VerifyKey, SigningKey, Signer, Verifier};
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::BigInt;

use super::CERTEXPIRYDAYS;
const ISSUER : &str = "MesaTEE";
const SUBJECT : &str = "MesaTEE";

pub type SK = Secp256r1Scalar;
pub type PK = Secp256r1Point;

pub fn p256_key_gen() -> (Secp256r1Scalar,Secp256r1Point){
    let sk: Secp256r1Scalar = Secp256r1Scalar::new_random();
    let base_point = Secp256r1Point::generator();
    let pk = base_point.scalar_mul(&sk.get_element());
    (sk,pk)
}

pub fn p256_sha256_sign(sk:Secp256r1Scalar,message:Vec<u8>) -> Vec<u8>{
    let signing_key = SigningKey::new(&sk.to_big_int().to_bytes()).unwrap();
    let signature = signing_key.sign(&message);
    signature.as_ref().to_vec()
}

pub fn p256_key_sign(sk:Secp256r1Scalar,message:Vec<u8>) -> (Vec<u8>,Vec<u8>){
    let q = Secp256r1Scalar::q();

    let r: Secp256r1Scalar = Secp256r1Scalar::new_random();
    let hash_m = HSha256::create_hash_from_slice(&message);
    let hash_m_s:Secp256r1Scalar = ECScalar::from(&hash_m);
    let tmp_mul = hash_m_s * sk;
    let s = BigInt::mod_sub(&r.to_big_int(), &tmp_mul.to_big_int(), &q);

    let r_b = r.to_big_int().to_bytes();
    let r_s = s.to_bytes();

    (r_b,r_s)
}

pub fn gen_ecc_cert(payload: String,
                    prv_k: &SK,
                    pub_k: &PK,
                    ecc_handle: &SgxEccHandle) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Generate public key bytes since both DER will use it
    let mut pub_key_bytes: Vec<u8> = vec![4];
    // let mut pk_gx = pub_k.gx.clone();
    let mut pk_gx = pub_k.x_coor().unwrap().to_bytes();
    pk_gx.reverse();
    // let mut pk_gy = pub_k.gy.clone();
    let mut pk_gy = pub_k.y_coor().unwrap().to_bytes();
    pk_gy.reverse();
    pub_key_bytes.extend_from_slice(&pk_gx);
    pub_key_bytes.extend_from_slice(&pk_gy);


    // Generate Certificate DER
    let cert_der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                // Certificate Version
                writer.next().write_tagged(yasna::Tag::context(0), |writer| {
                    writer.write_i8(2);
                });
                // Certificate Serial Number (unused but required)
                writer.next().write_u8(1);
                // Signature Algorithm: ecdsa-with-SHA256
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&ObjectIdentifier::from_slice(&[1,2,840,10045,4,3,2]));
                });
                // Issuer: CN=MesaTEE (unused but required)
                writer.next().write_sequence(|writer| {
                    writer.next().write_set(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&ObjectIdentifier::from_slice(&[2,5,4,3]));
                            writer.next().write_utf8_string(&ISSUER);
                        });
                    });
                });
                // Validity: Issuing/Expiring Time (unused but required)
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let issue_ts = TzUtc.timestamp(now.as_secs() as i64, 0);
                let expire = now + Duration::days(CERTEXPIRYDAYS).to_std().unwrap();
                let expire_ts = TzUtc.timestamp(expire.as_secs() as i64, 0);
                writer.next().write_sequence(|writer| {
                    writer.next().write_utctime(&yasna::models::UTCTime::from_datetime(&issue_ts));
                    writer.next().write_utctime(&yasna::models::UTCTime::from_datetime(&expire_ts));
                });
                // Subject: CN=MesaTEE (unused but required)
                writer.next().write_sequence(|writer| {
                    writer.next().write_set(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&ObjectIdentifier::from_slice(&[2,5,4,3]));
                            writer.next().write_utf8_string(&SUBJECT);
                        });
                    });
                });
                writer.next().write_sequence(|writer| {
                    // Public Key Algorithm
                    writer.next().write_sequence(|writer| {
                        // id-ecPublicKey
                        writer.next().write_oid(&ObjectIdentifier::from_slice(&[1,2,840,10045,2,1]));
                        // prime256v1
                        writer.next().write_oid(&ObjectIdentifier::from_slice(&[1,2,840,10045,3,1,7]));
                    });
                    // Public Key
                    writer.next().write_bitvec(&BitVec::from_bytes(&pub_key_bytes));
                });
                // Certificate V3 Extension
                writer.next().write_tagged(yasna::Tag::context(3), |writer| {
                    writer.write_sequence(|writer| {
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&ObjectIdentifier::from_slice(&[2,16,840,1,113730,1,13]));
                            writer.next().write_bytes(&payload.into_bytes());
                        });
                    });
                });
            });
            // Signature Algorithm: ecdsa-with-SHA256
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&ObjectIdentifier::from_slice(&[1,2,840,10045,4,3,2]));
            });
            // Signature
            let sig = {
                let tbs = &writer.buf[4..];
                // ecc_handle.ecdsa_sign_slice(tbs, &prv_k).unwrap()
                p256_sha256_sign(prv_k.into(),tbs.to_vec());
            };
            let sig_der = yasna::construct_der(|writer| {
                writer.write_sequence(|writer| {
                    let mut sig_x = sig.x.clone();
                    sig_x.reverse();
                    let mut sig_y = sig.y.clone();
                    sig_y.reverse();
                    writer.next().write_biguint(&BigUint::from_slice(&sig_x));
                    writer.next().write_biguint(&BigUint::from_slice(&sig_y));
                });
            });
            writer.next().write_bitvec(&BitVec::from_bytes(&sig_der));
        });
    });

    // Generate Private Key DER
    let key_der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u8(0);
            writer.next().write_sequence(|writer| {
                writer.next().write_oid(&ObjectIdentifier::from_slice(&[1,2,840,10045,2,1]));
                writer.next().write_oid(&ObjectIdentifier::from_slice(&[1,2,840,10045,3,1,7]));
            });
            let inner_key_der = yasna::construct_der(|writer| {
                writer.write_sequence(|writer| {
                    writer.next().write_u8(1);
                    // let mut prv_k_r = prv_k.r.clone();
                    // prv_k_r.reverse();
                    // writer.next().write_bytes(&prv_k_r);
                    let mut prv_k_r = prv_k.to_big_int().to_bytes();
                    prv_k_r.reverse();
                    writer.next().write_bytes(&prv_k_r);
                    writer.next().write_tagged(yasna::Tag::context(1), |writer| {
                        writer.write_bitvec(&BitVec::from_bytes(&pub_key_bytes));
                    });
                });
            });
            writer.next().write_bytes(&inner_key_der);
        });
    });

    Ok((key_der, cert_der))
}

pub fn percent_decode(orig: String) -> String {
    let v:Vec<&str> = orig.split("%").collect();
    let mut ret = String::new();
    ret.push_str(v[0]);
    if v.len() > 1 {
        for s in v[1..].iter() {
            ret.push(u8::from_str_radix(&s[0..2], 16).unwrap() as char);
            ret.push_str(&s[2..]);
        }
    }
    ret
}