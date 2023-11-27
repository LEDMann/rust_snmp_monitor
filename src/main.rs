use std::collections::BTreeMap;
use std::{str, env};
use std::net::{IpAddr, SocketAddr};

use std::time::{Duration, SystemTime};
use tokio::{task, time};

use chrono::offset::Local;
use chrono::DateTime;

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

#[derive(serde::Serialize)]
struct Record<'a> {
    time: &'a str,
    sys_name: &'a str,
    sys_contact: &'a str,
    ip_out_discards: u32,
    if_in_octets: String,
    if_out_octets: String,
}

async fn walk(ip: IpAddr, community: Vec<u8>, oid: &str) -> BTreeMap<ObjectIdentifier, ObjectValue> {

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

    // for (oid, value) in results {
    //     if value.is_string() {
    //         println!("{}: {:?}\n", oid, str::from_utf8(value.as_bytes().unwrap()).unwrap());
    //     } else {
    //         println!("{}: {:?}\n", oid, value);
    //     }
    // }

    results
}

async fn walk_bulk(ip: IpAddr, community: Vec<u8>, oid: &str, max_repetitions: u32) -> BTreeMap<ObjectIdentifier, ObjectValue> {

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

    // for (oid, value) in results {
    //     if value.is_string() {
    //         println!("{}: {:?}", oid, str::from_utf8(value.as_bytes().unwrap()).unwrap());
    //     } else {
    //         println!("{}: {:?}", oid, value);
    //     }
    // }
    // print!("\n");

    results
}

#[tokio::main]
async fn main() {

    let forever = task::spawn(async {

        // let currdir = env::current_dir().unwrap();

        let mut interval = time::interval(Duration::from_secs(15));

        let target_ip: IpAddr = TARGET_IP_STR.parse().unwrap();
        let community: Vec<u8> = COMMUNITY_STR.as_bytes().to_vec();

        // let currtime: DateTime<Local> = std::time::SystemTime::now().into();
        // let date = format!("{}", currtime.format("%Y_%m_%d %T"));

        let mut writer = csv::WriterBuilder::new().from_path("monitor_log.csv").unwrap();

        loop {
            interval.tick().await;
            let currtime: DateTime<Local> = std::time::SystemTime::now().into();
            let date = format!("{}", currtime.format("%Y_%m_%d %T"));
            println!("----------------------------------------------------------------------------");
            let sysname = walk(target_ip.clone(), community.clone(), OID_SYSNAME).await.into_iter().collect::<Vec<(ObjectIdentifier, ObjectValue)>>();
            let sys_name = str::from_utf8(&sysname.first().unwrap().1.as_bytes().unwrap()[0..]).unwrap();
            let syscontact = walk(target_ip.clone(), community.clone(), OID_SYSCONTACT).await.into_iter().collect::<Vec<(ObjectIdentifier, ObjectValue)>>();
            let sys_contact = str::from_utf8(&syscontact.first().unwrap().1.as_bytes().unwrap()[0..]).unwrap();
            let ipoutdiscards = walk(target_ip.clone(), community.clone(), OID_IPOUTDISCARDS).await.into_iter().collect::<Vec<(ObjectIdentifier, ObjectValue)>>().first().unwrap().clone().1.as_u32().unwrap();
            let ifinoctets = walk_bulk(target_ip.clone(), community.clone(), OID_IFINOCTETS, 50).await.into_iter().filter(|a| !a.1.is_unsigned32()).map(|a| a.1.as_u32().unwrap().to_string()).collect::<Vec<String>>().join(" | ");
            let ifoutoctets = walk_bulk(target_ip.clone(), community.clone(), OID_IFOUTOCTETS, 50).await.into_iter().filter(|a| !a.1.is_unsigned32()).map(|a| a.1.as_u32().unwrap().to_string()).collect::<Vec<String>>().join(" | ");
            println!("{}\n{}\n{}\n{}\n{}\n{}\n", date, sys_name, sys_contact, ipoutdiscards, ifinoctets, ifoutoctets);
            writer.serialize(Record {
                time : &date,
                sys_name : sys_name,
                sys_contact : sys_contact,
                ip_out_discards : ipoutdiscards,
                if_in_octets : ifinoctets,
                if_out_octets : ifoutoctets
            }).unwrap();
            writer.flush();
        }
    });

    forever.await;
}