use super::*;
use crate::cert::{gen_ecc_cert, p256_key_gen, SK, PK};
use crate::epid_quote::EpidQuote;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;

use rustls::*;
use std::io::{Read, Write};
use ring::signature::KeyPair;

pub type SignType = u64;

pub fn start_test_tls_server(){
    // generate key and cert
    let (key_der,cert_der) = generate_cert().unwrap();
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_der));
    let privkey = rustls::PrivateKey(key_der);

    // set config
    let mut config = rustls::ServerConfig::new(NoClientAuth::new());
    config
        .set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .unwrap();
    println!("==============start server====================");
    let mut sess = rustls::ServerSession::new(&std::sync::Arc::new(config));

    let listener = std::net::TcpListener::bind("127.0.0.1:5044").unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(mut socket) => {
                let mut tls = rustls::Stream::new(&mut sess,&mut socket);
                let mut plaintext = Vec::new(); //Vec::new();
                match tls.read_to_end(&mut plaintext) {
                    Ok(_) => println!("Client said: {}", std::str::from_utf8(&plaintext).unwrap()),
                    Err(e) => {
                        println!("Error in read_to_end: {:?}", e);
                        panic!("");
                    }
                };

                tls.write_all("hello back".as_bytes()).unwrap();
            }
            Err(e) => {
                println!("Error on accept {}", e);
            }
        }
    }

}


/// generate key and certification for tls server return (key_der,cert_der)
pub fn generate_cert() -> Result<(Vec<u8>,Vec<u8>),String>{
    let (pub_k,prv_k) = generate_key_pair();

    let  (a,b) = ring_key_gen_pcks_8();
    let pub_key = a.public_key().as_ref().to_vec(); // TODO:: put into create_attestation_report
    println!("==pub_key=={:?}",pub_key);
    println!("==pub_key=b={:?}",b);
    let (attn_report, sig, cert) = match create_attestation_report(pub_key, 0) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in create_attestation_report: {:?}", e);
            return Err("Error in create_attestation_report".to_string());
        }
    };
    let payload = attn_report + "|" + &sig + "|" + &cert;
    let cert_der= match cert::gen_ecc_cert(payload, a, b.clone()) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in gen_ecc_cert: {:?}", e);
            return Err("Error in gen_ecc_cert".to_string()); ;
        }
    };

    Ok((b,cert_der))
}

pub fn generate_key_pair() -> (PK, SK){
    let (prv_k, pub_k) = p256_key_gen();
    (pub_k,prv_k)
}

#[allow(const_err)]
pub fn create_attestation_report(pub_k: Vec<u8>, sign_type: SignType) -> Result<(String, String, String), String> {
    let mut  new = EpidQuote::new();
    new.get_group_id();

    // (2) Generate the report Fill ecc256 public key into report_data
    // let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    // let mut pub_k_gx = pub_k.x_coor().unwrap().to_bytes();
    // pub_k_gx.reverse();
    // let mut pub_k_gy =  pub_k.y_coor().unwrap().to_bytes();
    // pub_k_gy.reverse();
    // report_data.d[..32].clone_from_slice(&pub_k_gx);
    // report_data.d[32..].clone_from_slice(&pub_k_gy);

    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    let mut pub_k_gx = pub_k[1..33].to_vec();
    //pub_k_gx.reverse();
    report_data.d[..32].clone_from_slice(&pub_k_gx);
    let mut pub_k_gy = pub_k[33..].to_vec();
    //pub_k_gy.reverse();
    report_data.d[32..].clone_from_slice(&pub_k_gy);

    let rep = new.generate_quote_vec_report(report_data).unwrap();

    // Added 09-28-2018
    // Perform a check on qe_report to verify if the qe_report is valid
    new.verify_report();


    // let mut rhs_vec : Vec<u8> = new.quote_nonce.rand.to_vec();
    // rhs_vec.extend(&rep);
    // let rhs_hash = HSha256::create_hash_from_slice(&rhs_vec);
    //let lhs_hash = &qe_report.body.report_data.d[..32];
    //
    // println!("rhs hash = {:02X}", rhs_hash.iter().format(""));
    // println!("report hs= {:02X}", lhs_hash.iter().format(""));
    //
    // if rhs_hash != lhs_hash {
    //     println!("Quote is tampered!");
    //     return Err("Error".to_string());
    // }

    let (attn_report, sig, cert) = get_report_from_intel(rep);
    Ok((attn_report, sig, cert))
}