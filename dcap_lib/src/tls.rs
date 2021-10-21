use super::*;
use crate::cert::{gen_ecc_cert, p256_key_gen, SK, PK};
use crate::epid_quote::EpidQuote;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::arithmetic::Converter;

pub type SignType = u64;

pub fn generate_cert(){
    let (pub_k,prv_k) = generate_key_pair();
    let (attn_report, sig, cert) = match create_attestation_report(&pub_k, 0) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in create_attestation_report: {:?}", e);
            return ;
        }
    };
    let payload = attn_report + "|" + &sig + "|" + &cert;
    let (key_der, cert_der) = match cert::gen_ecc_cert(payload, &prv_k, &pub_k) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in gen_ecc_cert: {:?}", e);
            return ;
        }
    };
    println!("======================success==============================");
}

pub fn generate_key_pair() -> (PK, SK){
    let (prv_k, pub_k) = p256_key_gen();
    (pub_k,prv_k)
}

#[allow(const_err)]
pub fn create_attestation_report(pub_k: &PK, sign_type: SignType) -> Result<(String, String, String), String> {
    let mut  new = EpidQuote::new();
    new.get_group_id();

    // (2) Generate the report Fill ecc256 public key into report_data
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    let mut pub_k_gx = pub_k.x_coor().unwrap().to_bytes();
    pub_k_gx.reverse();
    let mut pub_k_gy =  pub_k.y_coor().unwrap().to_bytes();
    pub_k_gy.reverse();
    report_data.d[..32].clone_from_slice(&pub_k_gx);
    report_data.d[32..].clone_from_slice(&pub_k_gy);

    let rep = new.generate_quote_vec_report(report_data).unwrap();

    // Added 09-28-2018
    // Perform a check on qe_report to verify if the qe_report is valid
    new.verify_report();


    // let mut rhs_vec : Vec<u8> = quote_nonce.rand.to_vec();
    // rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
    // let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).unwrap();
    // let lhs_hash = &qe_report.body.report_data.d[..32];
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