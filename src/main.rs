use std::collections::BTreeMap;
use std::str;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;

use std::time::Duration;
use tokio::{task, time};

use csnmp::{ObjectIdentifier, Snmp2cClient, ObjectValue};


const TARGET_IP_STR: &str = "127.0.0.1";
const COMMUNITY_STR: &str = "public";

const OID_SYSCONTACT: &str = "1.3.6.1.2.1.1.4.0";
const OID_SYSNAME: &str = "1.3.6.1.2.1.1.5.0";

const OID_IFINOCTETS: &str = "1.3.6.1.2.1.2.2.1.10";
const OID_IFOUTOCTETS: &str = "1.3.6.1.2.1.2.2.1.16";

const OID_IFINDISCARDS: &str = "1.3.6.1.2.1.2.2.1.13";
const OID_IFOUTDISCARDS: &str = "1.3.6.1.2.1.2.2.1.19";

const OID_IPOUTDISCARDS: &str = "1.3.6.1.2.1.4.11.0";

async fn walk(ip: IpAddr, community: Vec<u8>, oid: &str) -> ExitCode {

    let sock_addr = SocketAddr::from((ip, 161));

    let client_res = Snmp2cClient::new(
        sock_addr,
        community,
        Some("0.0.0.0:0".parse().unwrap()),
        None,
    ).await;
    let client = client_res.expect("failed to create SNMP client");
    
    let top_oid: ObjectIdentifier = oid.parse().expect("failed to parse OID");

    // let mut results: Vec<BTreeMap<ObjectIdentifier, ObjectValue>> = vec![];
    
    let results_res = client.walk(
        top_oid
    ).await;
    let results = results_res.expect("failed to walk");

    for (oid, value) in results {
        if value.is_string() {
            println!("{}: {:?}\n", oid, str::from_utf8(value.as_bytes().unwrap()).unwrap());
        } else {
            println!("{}: {:?}\n", oid, value);
        }
    }

    ExitCode::SUCCESS
}

async fn walk_bulk(ip: IpAddr, community: Vec<u8>, oid: &str, max_repetitions: u32) -> ExitCode {

    let sock_addr = SocketAddr::from((ip, 161));

    let client_res = Snmp2cClient::new(
        sock_addr,
        community,
        Some("0.0.0.0:0".parse().unwrap()),
        None,
    ).await;
    let client = client_res.expect("failed to create SNMP client");
    
    let top_oid: ObjectIdentifier = oid.parse().expect("failed to parse OID");

    // let mut results: Vec<BTreeMap<ObjectIdentifier, ObjectValue>> = vec![];

    let results_res = client.walk_bulk(
        top_oid,
        max_repetitions
    ).await;
    let results = results_res.expect("failed to walk");

    for (oid, value) in results {
        if value.is_string() {
            println!("{}: {:?}", oid, str::from_utf8(value.as_bytes().unwrap()).unwrap());
        } else {
            println!("{}: {:?}", oid, value);
        }
    }
    print!("\n");

    ExitCode::SUCCESS
}

#[tokio::main]
async fn main() {

    let forever = task::spawn(async {
        let mut interval = time::interval(Duration::from_secs(15));

        let target_ip: IpAddr = TARGET_IP_STR.parse().unwrap();
        let community: Vec<u8> = COMMUNITY_STR.as_bytes().to_vec();

        loop {
            interval.tick().await;
            println!("----------------------------------------------------------------------------");
            walk(target_ip.clone(), community.clone(), OID_SYSCONTACT).await;
            walk(target_ip.clone(), community.clone(), OID_SYSNAME).await;
            walk(target_ip.clone(), community.clone(), OID_IPOUTDISCARDS).await;
            walk_bulk(target_ip.clone(), community.clone(), OID_IFINOCTETS, 50).await;
            walk_bulk(target_ip.clone(), community.clone(), OID_IFOUTOCTETS, 50).await;
            // walk_bulk(target_ip.clone(), community.clone(), OID_IFINDISCARDS, 50).await;
            // walk_bulk(target_ip.clone(), community.clone(), OID_IFOUTDISCARDS, 50).await;
        }
    });

    forever.await;
}