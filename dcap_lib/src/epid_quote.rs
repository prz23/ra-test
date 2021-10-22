use super::*;
use libc::*;

use std::ffi::CString;
use std::sync::Arc;
use std::net::TcpStream;
use std::io::{Write, Read};

use sgx_types::{
    sgx_report_data_t, sgx_ql_qv_result_t, sgx_spid_t, sgx_quote_nonce_t,
    sgx_quote_sign_type_t, sgx_epid_group_id_t
};
use rand_core::OsRng;
use rand_core::RngCore;

const SGXIOC_GET_EPID_GROUP_ID: c_ulong = 0x80047301;
const SGXIOC_GEN_EPID_QUOTE: c_ulong = 0xC0807302;
const QUOTE_BUF_LEN: usize = 2048;

pub const DEV_HOSTNAME:&'static str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX:&'static str = "/sgx/dev/attestation/v3/sigrl/";
pub const REPORT_SUFFIX:&'static str = "/sgx/dev/attestation/v3/report";
pub const CERTEXPIRYDAYS: i64 = 90i64;

#[repr(C)]
pub struct IoctlGenEPIDQuoteArg {
    report_data: sgx_report_data_t,    // Input
    quote_type: sgx_quote_sign_type_t, // Input
    spid: sgx_spid_t,                  // Input
    nonce: sgx_quote_nonce_t,          // Input
    sigrl_ptr: *const u8,              // Input (optional)
    sigrl_len: u32,                    // Input (optional)
    quote_buf_len: u32,                // Input
    quote_buf: *mut u8,                // Output
}

#[derive(Copy, Clone)]
pub struct EpidQuote {
    fd: c_int,
    pub group_id: sgx_epid_group_id_t,
    pub quote_nonce: sgx_quote_nonce_t,
}

impl EpidQuote {
    pub fn new() -> Self {
        println!("EpidQuote: new");

        let path =  CString::new("/dev/sgx").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), O_RDONLY) };
        if fd > 0 {
            Self {
                fd: fd,
                group_id: sgx_epid_group_id_t::default(),
                quote_nonce: sgx_quote_nonce_t::default()
            }
        } else {
            panic!("Open /dev/sgx failed")
        }
    }

    pub fn get_group_id(&mut self) -> u32 {
        println!("EpidQuote: get_group_id");

        let size: sgx_epid_group_id_t = sgx_epid_group_id_t::default();
        let ret = unsafe { libc::ioctl(self.fd, SGXIOC_GET_EPID_GROUP_ID, &size) };
        if ret < 0 {
            panic!("IOCTRL SGXIOC_GET_EPID_GROUP_ID failed");
        } else {
            self.group_id = size;
            as_u32_le(&size)
        }
    }

    pub fn read_spid(self) -> sgx_spid_t{
        let spid = "B6E792288644E2957A40AF226F5E4DD8";
        hex::decode_spid(&spid)
    }

    pub fn get_sigrl_data(self) -> (Vec<u8>,u32) {
        let sigrl_list = get_sigrl_from_intel(as_u32_le(&self.group_id));
        (sigrl_list.clone(),sigrl_list.len() as u32)
    }

    pub fn generate_quote_vec_report(&mut self,report_data:sgx_report_data_t) -> Result<Vec<u8>,&'static str>{
        let mut quote_buf: Vec<u8> = vec![0; QUOTE_BUF_LEN];
        let quote_ptr = quote_buf.as_mut_ptr();
        self.generate_quote(quote_ptr,report_data).expect("error");

        Ok(extract_quote(quote_buf))
    }

    pub fn generate_quote_vec(&mut self,report_data:&str) -> Result<Vec<u8>,&'static str>{

        let mut req_data = sgx_report_data_t::default();
        for (pos, val) in report_data.as_bytes().iter().enumerate() {
            req_data.d[pos] = *val;
        }

        let mut quote_buf: Vec<u8> = vec![0; QUOTE_BUF_LEN];
        let quote_ptr = quote_buf.as_mut_ptr();
        self.generate_quote(quote_ptr,req_data).expect("error");

        Ok(extract_quote(quote_buf))
    }

    pub fn generate_quote_nonce(&mut self) -> sgx_quote_nonce_t{
        let mut quote_nonce = sgx_quote_nonce_t { rand : [0;16] };
        OsRng.fill_bytes(&mut quote_nonce.rand);
        self.quote_nonce = quote_nonce.clone();
        return quote_nonce
    }

    pub fn generate_quote(&mut self, quote_buf: *mut u8,  report_data: sgx_report_data_t) -> Result<i32, &'static str> {
        println!("DcapQuote: generate_quote");
        let (sigrl,sigrl_len) = self.get_sigrl_data();
        let quote_arg: IoctlGenEPIDQuoteArg = IoctlGenEPIDQuoteArg {
            report_data: report_data.clone(),
            quote_type: sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE,
            spid: self.read_spid(),
            nonce: self.generate_quote_nonce(),
            sigrl_ptr: sigrl.as_ptr() as *const u8,
            sigrl_len: sigrl_len,
            quote_buf_len: QUOTE_BUF_LEN as u32,
            quote_buf: quote_buf,
        };

        let ret = unsafe { libc::ioctl(self.fd, SGXIOC_GEN_EPID_QUOTE, &quote_arg) };
        if ret < 0 {
            Err("IOCTRL SGXIOC_GEN_DCAP_QUOTE failed")
        } else {
            println!("quote_buf {:?}",quote_buf);
            Ok( 0 )
        }
    }

    pub fn get_report_from_intel(self,quote_vec:Vec<u8>) -> (String, String, String){
        get_report_from_intel(quote_vec)
    }

    pub fn verify_report(self){
        println!("unimplentment");
    }

}

pub fn get_sigrl_from_intel(gid : u32) -> Vec<u8> {
    println!("get_sigrl_from_intel ");
    let config = make_ias_client_config();
    let ias_key = get_ias_api_key();

    let req = format!("GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
                      SIGRL_SUFFIX,
                      gid,
                      DEV_HOSTNAME,
                      ias_key);

    println!("{}", req);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = connect_to_intel();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    println!("write complete");

    match tls.read_to_end(&mut plaintext) {
        Ok(_) => (),
        Err(e) => {
            println!("get_sigrl_from_intel tls.read_to_end: {:?}", e);
            panic!("haha");
        }
    }
    println!("read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    println!("{}", resp_string);

    parse_response_sigrl(&plaintext)
}

fn parse_response_sigrl(resp : &[u8]) -> Vec<u8> {
    println!("parse_response_sigrl");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp   = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    println!("parse result {:?}", result);
    println!("parse response{:?}", respp);

    let msg : &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. ",
        _ => msg = "Unknown error occured",
    }

    println!("{}", msg);
    let mut len_num : u32 = 0;

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        if h.name == "content-length" {
            let len_str = String::from_utf8(h.value.to_vec()).unwrap();
            len_num = len_str.parse::<u32>().unwrap();
            println!("content length = {}", len_num);
        }
    }

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        println!("Base64-encoded SigRL: {:?}", resp_body);

        return base64::decode(std::str::from_utf8(resp_body).unwrap()).unwrap();
    }

    // len_num == 0
    Vec::new()
}

pub fn make_ias_client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    config
}

fn get_ias_api_key() -> String {
    "22aa549a2d5e47a2933a753c1cae947c".to_string()
}

fn connect_to_intel() -> TcpStream{
    let port = 443;
    let hostname = "api.trustedservices.intel.com";
    //let addr = lookup_ipv4(hostname, port);
    let sock = TcpStream::connect("40.87.90.88:443").expect("[-] Connect tls server failed!");
    sock
}

pub fn lookup_ipv4(host: &str, port: u16) -> std::net::SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let std::net::SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}

pub fn get_report_from_intel(quote : Vec<u8>) -> (String, String, String){
    let config = make_ias_client_config();
    let encoded_quote = base64::encode(&quote[..]);
    let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);
    let ias_key = get_ias_api_key();

    let req = format!("POST {} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                      REPORT_SUFFIX,
                      DEV_HOSTNAME,
                      ias_key,
                      encoded_json.len(),
                      encoded_json);

    println!("{}", req);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = connect_to_intel();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    println!("write complete");

    tls.read_to_end(&mut plaintext).unwrap();
    println!("read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    println!("resp_string = {}", resp_string);
    let (attn_report, sig, cert) = parse_response_attn_report(&plaintext);

    (attn_report, sig, cert)
}

fn parse_response_attn_report(resp : &[u8]) -> (String, String, String){
    println!("parse_response_attn_report");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp   = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    println!("parse result {:?}", result);

    let msg : &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. ",
        _ => {println!("DBG:{}", respp.code.unwrap()); msg = "Unknown error occured"},
    }

    println!("{}", msg);
    let mut len_num : u32 = 0;

    let mut sig = String::new();
    let mut cert = String::new();
    let mut attn_report = String::new();

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        //println!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
        match h.name{
            "Content-Length" => {
                let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                len_num = len_str.parse::<u32>().unwrap();
                println!("content length = {}", len_num);
            }
            "X-IASReport-Signature" => sig = std::str::from_utf8(h.value).unwrap().to_string(),
            "X-IASReport-Signing-Certificate" => cert = std::str::from_utf8(h.value).unwrap().to_string(),
            _ => (),
        }
    }

    // Remove %0A from cert, and only obtain the signing cert
    cert = cert.replace("%0A", "");
    cert = cert::percent_decode(cert);
    let v: Vec<&str> = cert.split("-----").collect();
    let sig_cert = v[2].to_string();

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        attn_report = std::str::from_utf8(resp_body).unwrap().to_string();
        println!("Attestation report: {}", attn_report);
    }

    // len_num == 0
    (attn_report, sig, sig_cert)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) <<  0) +
        ((array[1] as u32) <<  8) +
        ((array[2] as u32) << 16) +
        ((array[3] as u32) << 24)
}

pub fn extract_quote(input:Vec<u8>) -> Vec<u8>{
    let mut index = 0;
    for i in (1..QUOTE_BUF_LEN){
        let ind = QUOTE_BUF_LEN - i;
        if input[ind] != 0u8{
            index = ind;
            break;
        }
    }
    input[..index+1].to_vec()
}