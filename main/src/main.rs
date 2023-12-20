#![allow(non_snake_case, non_camel_case_types)]

mod mibobject;

use chrono::Utc;
use mibobject::MibModule::MibObject;

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::str::FromStr;
use std::net::{IpAddr, SocketAddr};

use std::sync::mpsc::{Sender, Receiver};
use std::time::Duration;
use async_trait::async_trait;
use csv::Error;
use egui::{Response, Widget};
use egui_extras::{TableBuilder, Column};
use egui_dock::{DockArea, DockState, NodeIndex, Style, TabViewer};
use tokio::runtime::Builder;
use tokio::{task, time};

use serde_json;

use eframe::{egui, AppCreator};

use csnmp::{Snmp2cClient, ObjectValue, client, ObjectIdentifier};


struct SnmpMonitorApp {
    name: String,
    target_ip: IpAddr,
    community: String,
    mib_obj_reciever: Receiver<MibObject>,
    object: Option<MibObject>,
}

#[tokio::main]
async fn main() {    
    println!("start");
    let (mib_obj_sender, mib_obj_reciever) = std::sync::mpsc::channel();


    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("SNMP Monitor".to_string()).with_app_id("SNMP_Monitor").with_min_inner_size([854.0,480.0]).with_maximized(true),
        ..Default::default()
    };

    let app: AppCreator = Box::new(|_| Box::new(SnmpMonitorApp { 
        name: "SNMP_Monitor".to_owned(), 
        target_ip: IpAddr::from_str("127.0.0.1").unwrap(), 
        community: "public".to_owned(), 
        mib_obj_reciever: mib_obj_reciever, 
        object: None,
    }));

    println!("create task");

    let runtime = Builder::new_multi_thread()
                                .thread_stack_size(16 * 1024 * 1024)
                                .thread_name("monitoring_thread")
                                .worker_threads(1)
                                .enable_time()
                                .enable_io()
                                .build()
                                .unwrap();

    println!("run task");

    runtime.spawn(async move {
        println!("inside task");
        let mut interval = time::interval(Duration::from_secs(30));

        let mut target_ip = IpAddr::from_str("127.0.0.1").unwrap();
        let mut community = "public".to_owned();

        // let currtime: DateTime<Local> = std::time::SystemTime::now().into();
        // let date = format!("{}", currtime.format("%Y_%m_%d %T"));

        // let mut writer = csv::WriterBuilder::new().from_path("monitor_log.csv").unwrap();

        let sock_addr = SocketAddr::from((target_ip.to_owned(), 161));

        let client_res = Snmp2cClient::new(
            sock_addr,
            community.as_bytes().to_vec().clone(),
            Some("0.0.0.0:0".parse().unwrap()),
            None,
        ).await;
        let client = client_res.expect("failed to create SNMP client");
        println!("start loop");
        
        let log_file_name = format!("MIB-log-{}.json", Utc::now().format("%d-%m-%Y"));

        let log = OpenOptions::new()
                                    .read(true)
                                    .append(true)
                                    .create(true)
                                    .open(log_file_name)
                                    .unwrap();

        let mut log_writer = BufWriter::new(log);

        'monitor_loop: loop {
            println!("loop repeat");
            interval.tick().await;
            
            let mut object = MibObject::new();

            println!("sending snmp requests");

            object.walk(&client).await;
            
            println!("got snmp responses");
            
            println!("object size: {}", std::mem::size_of_val(&object));

            // println!("{:?}, {:?}", &object.icmp.icmpOutMsgs.name, &object.icmp.icmpOutMsgs.value);

            // write!(log_writer, "{},\n", serde_json::to_string_pretty(&object).unwrap());
            write!(log_writer, "{},\n", serde_json::to_string(&object).unwrap());
            // history_writer.flush().unwrap();

            mib_obj_sender.send(object).expect("msg");
        }

    });

    println!("run egui");

    eframe::run_native("SNMP Monitor", options, app).unwrap();
}

impl eframe::App for SnmpMonitorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        match self.mib_obj_reciever.try_recv() {
            Ok(mibobj) => {
                println!("recieved object");
                self.object = Some(mibobj);
            },
            Err(_) => {},
        };
        match &self.object {
            Some(mibobj) => {
                egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
                    ui.heading("top panel");
                });
                egui::SidePanel::left("side_panel").show(ctx, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.collapsing("System", |ui| {
                            ui.collapsing(&mibobj.system.sysDesc.name,     |ui| match &mibobj.system.sysDesc.value.len()     { 1 => ui.label(mibobj.system.sysDesc.value.first().unwrap()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.system.sysObjectID.name, |ui| match &mibobj.system.sysObjectID.value.len() { 1 => ui.label(mibobj.system.sysObjectID.value.first().unwrap().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".")), _ => ui.spinner() });
                            ui.collapsing(&mibobj.system.sysUpTime.name,   |ui| match &mibobj.system.sysUpTime.value.len()   { 1 => ui.label(mibobj.system.sysUpTime.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.system.sysContact.name,  |ui| match &mibobj.system.sysContact.value.len()  { 1 => ui.label(mibobj.system.sysContact.value.first().unwrap()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.system.sysName.name,     |ui| match &mibobj.system.sysName.value.len()     { 1 => ui.label(mibobj.system.sysName.value.first().unwrap()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.system.sysLocation.name, |ui| match &mibobj.system.sysLocation.value.len() { 1 => ui.label(mibobj.system.sysLocation.value.first().unwrap()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.system.sysServices.name, |ui| match &mibobj.system.sysServices.value.len() { 1 => ui.label(mibobj.system.sysServices.value.first().unwrap().to_string()), _ => ui.spinner() });
                        });
                        ui.collapsing("Interfaces", |ui| {
                            ui.collapsing(&mibobj.interfaces.ifNumber.name,     |ui| match &mibobj.interfaces.ifNumber.value.len()     { 1 => ui.label(mibobj.interfaces.ifNumber.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing("ifTable", |ui| {
                                egui::ScrollArea::horizontal().auto_shrink(false).show(ui, |ui| {
                                    TableBuilder::new(ui)
                                        .striped(true)
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifIndex
                                        .column(Column::auto_with_initial_suggestion(300.0).at_least(100.0).resizable(true))    // ifDescr
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifType
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifMtu
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifSpeed
                                        .column(Column::auto_with_initial_suggestion(200.0).at_least(50.0).resizable(true))     // ifPhysAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifAdminStatus
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifOperStatus
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifLastChange
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifInOctets
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifInUcastPkts
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifInNUcastPkts
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifInDiscards
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifInErrors
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifInUnknownProtos
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifOutOctets
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifOutUcastPkts
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifOutNUcastPkts
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifOutDiscards
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifOutErrors
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifOutQLen
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // ifSpecific
                                        .header(26.0, |mut header| {
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifIndex.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifDescr.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifType.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifMtu.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifSpeed.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifPhysAddress.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifAdminStatus.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifOperStatus.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifLastChange.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifInOctets.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifInUcastPkts.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifInNUcastPkts.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifInDiscards.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifInErrors.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifInUnknownProtos.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifOutOctets.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifOutUcastPkts.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifOutNUcastPkts.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifOutDiscards.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifOutErrors.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifOutQLen.name); });
                                            header.col(|ui| { ui.strong(&mibobj.interfaces.ifTable.ifSpecific.name); });
                                        })
                                        .body(|body| {
                                            body.rows(26.0, mibobj.interfaces.ifTable.ifIndex.value.len(), |index, mut row| {
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifIndex.value.len().cmp(&0)           { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifIndex.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifDescr.value.len().cmp(&0)           { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifDescr.value.clone().get(index).unwrap()); }, _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifType.value.len().cmp(&0)            { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifType.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifMtu.value.len().cmp(&0)             { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifMtu.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifSpeed.value.len().cmp(&0)           { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifSpeed.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifPhysAddress.value.len().cmp(&0)     { std::cmp::Ordering::Greater => { ui.label(format!("{:02x?}", mibobj.interfaces.ifTable.ifPhysAddress.value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifAdminStatus.value.len().cmp(&0)     { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifAdminStatus.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifOperStatus.value.len().cmp(&0)      { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifOperStatus.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifLastChange.value.len().cmp(&0)      { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifLastChange.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifInOctets.value.len().cmp(&0)        { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifInOctets.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifInUcastPkts.value.len().cmp(&0)     { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifInUcastPkts.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifInNUcastPkts.value.len().cmp(&0)    { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifInNUcastPkts.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifInDiscards.value.len().cmp(&0)      { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifInDiscards.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifInErrors.value.len().cmp(&0)        { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifInErrors.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifInUnknownProtos.value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifInUnknownProtos.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifOutOctets.value.len().cmp(&0)       { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifOutOctets.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifOutUcastPkts.value.len().cmp(&0)    { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifOutUcastPkts.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifOutNUcastPkts.value.len().cmp(&0)   { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifOutNUcastPkts.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifOutDiscards.value.len().cmp(&0)     { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifOutDiscards.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifOutErrors.value.len().cmp(&0)       { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifOutErrors.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifOutQLen.value.len().cmp(&0)         { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifOutQLen.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.interfaces.ifTable.ifSpecific.value.len().cmp(&0)        { std::cmp::Ordering::Greater => { ui.label(mibobj.interfaces.ifTable.ifSpecific.value.clone().get(index).unwrap().into_iter().map(|b| b.to_string()).collect::<Vec<String>>().join(".")); }, _ => { ui.spinner(); } });
                                        });
                                    });
                                });
                            });
                        });
                        ui.collapsing("at", |ui| {
                            ui.collapsing("atTable", |ui| {
                                egui::ScrollArea::horizontal().auto_shrink(false).show(ui, |ui| {
                                    TableBuilder::new(ui)
                                        .striped(true)
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atIfIndex
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atPhysAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .header(26.0, |mut header| {
                                            header.col(|ui| { ui.strong(&mibobj.at.atTable.atIfIndex.name); });
                                            header.col(|ui| { ui.strong(&mibobj.at.atTable.atPhysAddress.name); });
                                            header.col(|ui| { ui.strong(&mibobj.at.atTable.atNetAddress.name); });
                                        })
                                        .body(|body| {
                                            body.rows(26.0, mibobj.at.atTable.atIfIndex.value.len(), |index, mut row| {
                                                row.col(|ui| match &mibobj.at.atTable.atIfIndex.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.at.atTable.atIfIndex.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.at.atTable.atPhysAddress.value.len().cmp(&0)             { std::cmp::Ordering::Greater => { ui.label(format!("{:02x?}", mibobj.at.atTable.atPhysAddress.value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.at.atTable.atNetAddress.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", mibobj.at.atTable.atNetAddress.value.clone().get(index).unwrap())); } _ => { ui.spinner(); } });
                                        });
                                    });
                                });
                            });
                        });
                        ui.collapsing("ip", |ui| {
                            ui.collapsing(&mibobj.ip.ipForwarding.name,     |ui| match &mibobj.ip.ipForwarding.value.len()     { 1 => ui.label(mibobj.ip.ipForwarding.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipDefaultTTL.name,     |ui| match &mibobj.ip.ipDefaultTTL.value.len()     { 1 => ui.label(mibobj.ip.ipDefaultTTL.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipInReceives.name,     |ui| match &mibobj.ip.ipInReceives.value.len()     { 1 => ui.label(mibobj.ip.ipInReceives.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipInHdrErrors.name,     |ui| match &mibobj.ip.ipInHdrErrors.value.len()     { 1 => ui.label(mibobj.ip.ipInHdrErrors.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipInAddrErrors.name,     |ui| match &mibobj.ip.ipInAddrErrors.value.len()     { 1 => ui.label(mibobj.ip.ipInAddrErrors.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipForwDatagrams.name,     |ui| match &mibobj.ip.ipForwDatagrams.value.len()     { 1 => ui.label(mibobj.ip.ipForwDatagrams.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipInUnknownProtos.name,     |ui| match &mibobj.ip.ipInUnknownProtos.value.len()     { 1 => ui.label(mibobj.ip.ipInUnknownProtos.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipInDiscards.name,     |ui| match &mibobj.ip.ipInDiscards.value.len()     { 1 => ui.label(mibobj.ip.ipInDiscards.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipInDelivers.name,     |ui| match &mibobj.ip.ipInDelivers.value.len()     { 1 => ui.label(mibobj.ip.ipInDelivers.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipOutRequests.name,     |ui| match &mibobj.ip.ipOutRequests.value.len()     { 1 => ui.label(mibobj.ip.ipOutRequests.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipOutDiscards.name,     |ui| match &mibobj.ip.ipOutDiscards.value.len()     { 1 => ui.label(mibobj.ip.ipOutDiscards.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipOutNoRoutes.name,     |ui| match &mibobj.ip.ipOutNoRoutes.value.len()     { 1 => ui.label(mibobj.ip.ipOutNoRoutes.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipReasmTimeout.name,     |ui| match &mibobj.ip.ipReasmTimeout.value.len()     { 1 => ui.label(mibobj.ip.ipReasmTimeout.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipReasmReqds.name,     |ui| match &mibobj.ip.ipReasmReqds.value.len()     { 1 => ui.label(mibobj.ip.ipReasmReqds.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipReasmOKs.name,     |ui| match &mibobj.ip.ipReasmOKs.value.len()     { 1 => ui.label(mibobj.ip.ipReasmOKs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipReasmFails.name,     |ui| match &mibobj.ip.ipReasmFails.value.len()     { 1 => ui.label(mibobj.ip.ipReasmFails.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipFragOKs.name,     |ui| match &mibobj.ip.ipFragOKs.value.len()     { 1 => ui.label(mibobj.ip.ipFragOKs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipFragFails.name,     |ui| match &mibobj.ip.ipFragFails.value.len()     { 1 => ui.label(mibobj.ip.ipFragFails.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.ip.ipFragCreates.name,     |ui| match &mibobj.ip.ipFragCreates.value.len()     { 1 => ui.label(mibobj.ip.ipFragCreates.value.first().unwrap().to_string()), _ => ui.spinner() });

                            // ipAddrTable
                            ui.collapsing("ipAddrtable", |ui| {
                                egui::ScrollArea::horizontal().auto_shrink(false).show(ui, |ui| {
                                    TableBuilder::new(ui)
                                        .striped(true)
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atIfIndex
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atPhysAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .header(26.0, |mut header| {
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipAddrTable.ipAdEntAddr.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipAddrTable.ipAdEntIfIndex.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipAddrTable.ipAdEntNetMask.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipAddrTable.ipAdEntBcastAddr.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipAddrTable.ipAdEntReasmMaxSize.name); });
                                        })
                                        .body(|body| {
                                            body.rows(26.0, mibobj.ip.ipAddrTable.ipAdEntAddr.value.len(), |index, mut row| {
                                                row.col(|ui| match &mibobj.ip.ipAddrTable.ipAdEntAddr.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", mibobj.ip.ipAddrTable.ipAdEntAddr.value.clone().get(index).unwrap())); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipAddrTable.ipAdEntIfIndex.value.len().cmp(&0)             { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipAddrTable.ipAdEntIfIndex.value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipAddrTable.ipAdEntNetMask.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", mibobj.ip.ipAddrTable.ipAdEntNetMask.value.clone().get(index).unwrap())); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipAddrTable.ipAdEntBcastAddr.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipAddrTable.ipAdEntBcastAddr.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipAddrTable.ipAdEntReasmMaxSize.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipAddrTable.ipAdEntReasmMaxSize.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                            });
                                    });
                                });
                            });
                            // ipRouteTable
                            ui.collapsing("ipRouteTable", |ui| {
                                egui::ScrollArea::horizontal().auto_shrink(false).show(ui, |ui| {
                                    TableBuilder::new(ui)
                                        .striped(true)
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atIfIndex
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atPhysAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .header(26.0, |mut header| {
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipRouteTable.ipRouteDest.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipRouteTable.ipRouteIfIndex.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipRouteTable.ipRouteMetric1.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipRouteTable.ipRouteMetric2.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipRouteTable.ipRouteMetric3.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipRouteTable.ipRouteMetric4.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipRouteTable.ipRouteNextHop.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipRouteTable.ipRouteType.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipRouteTable.ipRouteProto.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipRouteTable.ipRouteAge.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipRouteTable.ipRouteMask.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipRouteTable.ipRouteMetric5.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipRouteTable.ipRouteInfo.name); });
                                        })
                                        .body(|body| {
                                            body.rows(26.0, mibobj.ip.ipRouteTable.ipRouteIfIndex.value.len(), |index, mut row| {
                                                row.col(|ui| match &mibobj.ip.ipRouteTable.ipRouteDest.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", mibobj.ip.ipRouteTable.ipRouteDest.value.clone().get(index).unwrap())); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipRouteTable.ipRouteIfIndex.value.len().cmp(&0)             { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipRouteTable.ipRouteIfIndex.value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipRouteTable.ipRouteMetric1.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipRouteTable.ipRouteMetric1.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipRouteTable.ipRouteMetric2.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipRouteTable.ipRouteMetric2.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipRouteTable.ipRouteMetric3.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipRouteTable.ipRouteMetric3.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipRouteTable.ipRouteMetric4.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipRouteTable.ipRouteMetric4.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipRouteTable.ipRouteNextHop.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", mibobj.ip.ipRouteTable.ipRouteNextHop.value.clone().get(index).unwrap())); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipRouteTable.ipRouteType.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipRouteTable.ipRouteType.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipRouteTable.ipRouteProto.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipRouteTable.ipRouteProto.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipRouteTable.ipRouteAge.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipRouteTable.ipRouteAge.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipRouteTable.ipRouteMask.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", mibobj.ip.ipRouteTable.ipRouteMask.value.clone().get(index).unwrap())); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipRouteTable.ipRouteMetric5.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipRouteTable.ipRouteMetric5.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipRouteTable.ipRouteInfo.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(format!("{:02x?}", mibobj.ip.ipRouteTable.ipRouteInfo.value.clone().get(index).unwrap())); } _ => { ui.spinner(); } });
                                            });
                                    });
                                });
                            });
                            // ipNetToMediaTable
                            ui.collapsing("ipNetToMediaTable", |ui| {
                                egui::ScrollArea::horizontal().auto_shrink(false).show(ui, |ui| {
                                    TableBuilder::new(ui)
                                        .striped(true)
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atIfIndex
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atPhysAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .header(26.0, |mut header| {
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipNetToMediaTable.ipNetToMediaIfIndex.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipNetToMediaTable.ipNetToMediaPhysAddress.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipNetToMediaTable.ipNetToMediaNetAddress.name); });
                                            header.col(|ui| { ui.strong(&mibobj.ip.ipNetToMediaTable.ipNetToMediaType.name); });
                                        })
                                        .body(|body| {
                                            body.rows(26.0, mibobj.ip.ipNetToMediaTable.ipNetToMediaIfIndex.value.len(), |index, mut row| {
                                                row.col(|ui| match &mibobj.ip.ipNetToMediaTable.ipNetToMediaIfIndex.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipNetToMediaTable.ipNetToMediaIfIndex.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipNetToMediaTable.ipNetToMediaPhysAddress.value.len().cmp(&0)             { std::cmp::Ordering::Greater => { ui.label(format!("{:02x?}", mibobj.ip.ipNetToMediaTable.ipNetToMediaPhysAddress.value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipNetToMediaTable.ipNetToMediaNetAddress.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", mibobj.ip.ipNetToMediaTable.ipNetToMediaNetAddress.value.clone().get(index).unwrap())); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.ip.ipNetToMediaTable.ipNetToMediaType.value.len().cmp(&0)                    { std::cmp::Ordering::Greater => { ui.label(mibobj.ip.ipNetToMediaTable.ipNetToMediaType.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                            });
                                    });
                                });
                            });
                            ui.collapsing(&mibobj.ip.ipRoutingDiscards.name,     |ui| match &mibobj.ip.ipRoutingDiscards.value.len()     { 1 => ui.label(mibobj.ip.ipRoutingDiscards.value.first().unwrap().to_string()), _ => ui.spinner() });
                        });
                        ui.collapsing("Icmp", |ui| {
                            ui.collapsing(&mibobj.icmp.icmpInMsgs.name,     |ui| match &mibobj.icmp.icmpInMsgs.value.len()     { 1 => ui.label(mibobj.icmp.icmpInMsgs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpInErrors.name,     |ui| match &mibobj.icmp.icmpInErrors.value.len()     { 1 => ui.label(mibobj.icmp.icmpInErrors.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpInDestUnreachs.name,     |ui| match &mibobj.icmp.icmpInDestUnreachs.value.len()     { 1 => ui.label(mibobj.icmp.icmpInDestUnreachs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpInTimeExcds.name,     |ui| match &mibobj.icmp.icmpInTimeExcds.value.len()     { 1 => ui.label(mibobj.icmp.icmpInTimeExcds.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpInParmProbs.name,     |ui| match &mibobj.icmp.icmpInParmProbs.value.len()     { 1 => ui.label(mibobj.icmp.icmpInParmProbs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpInSrcQuenchs.name,     |ui| match &mibobj.icmp.icmpInSrcQuenchs.value.len()     { 1 => ui.label(mibobj.icmp.icmpInSrcQuenchs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpInRedirects.name,     |ui| match &mibobj.icmp.icmpInRedirects.value.len()     { 1 => ui.label(mibobj.icmp.icmpInRedirects.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpInEchos.name,     |ui| match &mibobj.icmp.icmpInEchos.value.len()     { 1 => ui.label(mibobj.icmp.icmpInEchos.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpInEchoReps.name,     |ui| match &mibobj.icmp.icmpInEchoReps.value.len()     { 1 => ui.label(mibobj.icmp.icmpInEchoReps.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpInTimestamps.name,     |ui| match &mibobj.icmp.icmpInTimestamps.value.len()     { 1 => ui.label(mibobj.icmp.icmpInTimestamps.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpInTimestampReps.name,     |ui| match &mibobj.icmp.icmpInTimestampReps.value.len()     { 1 => ui.label(mibobj.icmp.icmpInTimestampReps.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpInAddrMasks.name,     |ui| match &mibobj.icmp.icmpInAddrMasks.value.len()     { 1 => ui.label(mibobj.icmp.icmpInAddrMasks.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpInAddrMaskReps.name,     |ui| match &mibobj.icmp.icmpInAddrMaskReps.value.len()     { 1 => ui.label(mibobj.icmp.icmpInAddrMaskReps.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpOutMsgs.name,     |ui| match &mibobj.icmp.icmpOutMsgs.value.len()     { 1 => ui.label(mibobj.icmp.icmpOutMsgs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpOutErrors.name,     |ui| match &mibobj.icmp.icmpOutErrors.value.len()     { 1 => ui.label(mibobj.icmp.icmpOutErrors.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpOutDestUnreachs.name,     |ui| match &mibobj.icmp.icmpOutDestUnreachs.value.len()     { 1 => ui.label(mibobj.icmp.icmpOutDestUnreachs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpOutTimeExcds.name,     |ui| match &mibobj.icmp.icmpOutTimeExcds.value.len()     { 1 => ui.label(mibobj.icmp.icmpOutTimeExcds.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpOutParmProbs.name,     |ui| match &mibobj.icmp.icmpOutParmProbs.value.len()     { 1 => ui.label(mibobj.icmp.icmpOutParmProbs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpOutSrcQuenchs.name,     |ui| match &mibobj.icmp.icmpOutSrcQuenchs.value.len()     { 1 => ui.label(mibobj.icmp.icmpOutSrcQuenchs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpOutRedirects.name,     |ui| match &mibobj.icmp.icmpOutRedirects.value.len()     { 1 => ui.label(mibobj.icmp.icmpOutRedirects.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpOutEchos.name,     |ui| match &mibobj.icmp.icmpOutEchos.value.len()     { 1 => ui.label(mibobj.icmp.icmpOutEchos.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpOutEchoReps.name,     |ui| match &mibobj.icmp.icmpOutEchoReps.value.len()     { 1 => ui.label(mibobj.icmp.icmpOutEchoReps.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpOutTimestamps.name,     |ui| match &mibobj.icmp.icmpOutTimestamps.value.len()     { 1 => ui.label(mibobj.icmp.icmpOutTimestamps.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpOutTimestampReps.name,     |ui| match &mibobj.icmp.icmpOutTimestampReps.value.len()     { 1 => ui.label(mibobj.icmp.icmpOutTimestampReps.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpOutAddrMasks.name,     |ui| match &mibobj.icmp.icmpOutAddrMasks.value.len()     { 1 => ui.label(mibobj.icmp.icmpOutAddrMasks.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.icmp.icmpOutAddrMaskReps.name,     |ui| match &mibobj.icmp.icmpOutAddrMaskReps.value.len()     { 1 => ui.label(mibobj.icmp.icmpOutAddrMaskReps.value.first().unwrap().to_string()), _ => ui.spinner() });
                        });
                        ui.collapsing("Tcp", |ui| {
                            ui.collapsing(&mibobj.tcp.tcpRtoAlgorithm.name, |ui| match &mibobj.tcp.tcpRtoAlgorithm.value.len()     { 1 => ui.label(mibobj.tcp.tcpRtoAlgorithm.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.tcp.tcpRtoMin.name, |ui| match &mibobj.tcp.tcpRtoMin.value.len()     { 1 => ui.label(mibobj.tcp.tcpRtoMin.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.tcp.tcpRtoMax.name, |ui| match &mibobj.tcp.tcpRtoMax.value.len()     { 1 => ui.label(mibobj.tcp.tcpRtoMax.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.tcp.tcpMaxConn.name, |ui| match &mibobj.tcp.tcpMaxConn.value.len()     { 1 => ui.label(mibobj.tcp.tcpMaxConn.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.tcp.tcpActiveOpens.name, |ui| match &mibobj.tcp.tcpActiveOpens.value.len()     { 1 => ui.label(mibobj.tcp.tcpActiveOpens.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.tcp.tcpPassiveOpens.name, |ui| match &mibobj.tcp.tcpPassiveOpens.value.len()     { 1 => ui.label(mibobj.tcp.tcpPassiveOpens.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.tcp.tcpAttemptFails.name, |ui| match &mibobj.tcp.tcpAttemptFails.value.len()     { 1 => ui.label(mibobj.tcp.tcpAttemptFails.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.tcp.tcpEstabResets.name, |ui| match &mibobj.tcp.tcpEstabResets.value.len()     { 1 => ui.label(mibobj.tcp.tcpEstabResets.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.tcp.tcpCurrEstab.name, |ui| match &mibobj.tcp.tcpCurrEstab.value.len()     { 1 => ui.label(mibobj.tcp.tcpCurrEstab.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.tcp.tcpInSegs.name, |ui| match &mibobj.tcp.tcpInSegs.value.len()     { 1 => ui.label(mibobj.tcp.tcpInSegs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.tcp.tcpOutSegs.name, |ui| match &mibobj.tcp.tcpOutSegs.value.len()     { 1 => ui.label(mibobj.tcp.tcpOutSegs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.tcp.tcpRetransSegs.name, |ui| match &mibobj.tcp.tcpRetransSegs.value.len()     { 1 => ui.label(mibobj.tcp.tcpRetransSegs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            

                            ui.collapsing("TcpConnTable", |ui| {
                                egui::ScrollArea::horizontal().auto_shrink(false).show(ui, |ui| {
                                    TableBuilder::new(ui)
                                        .striped(true)
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atIfIndex
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atPhysAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atNetAddress
                                        .header(26.0, |mut header| {
                                            header.col(|ui| { ui.strong(&mibobj.tcp.tcpConnTable.tcpConnState.name); });
                                            header.col(|ui| { ui.strong(&mibobj.tcp.tcpConnTable.tcpConnLocalAddress.name); });
                                            header.col(|ui| { ui.strong(&mibobj.tcp.tcpConnTable.tcpConnLocalPort.name); });
                                            header.col(|ui| { ui.strong(&mibobj.tcp.tcpConnTable.tcpConnRemAddress.name); });
                                            header.col(|ui| { ui.strong(&mibobj.tcp.tcpConnTable.tcpConnRemPort.name); });
                                        })
                                        .body(|body| {
                                            body.rows(26.0, mibobj.tcp.tcpConnTable.tcpConnState.value.len(), |index, mut row| {
                                                row.col(|ui| match &mibobj.tcp.tcpConnTable.tcpConnState.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.tcp.tcpConnTable.tcpConnState.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.tcp.tcpConnTable.tcpConnLocalAddress.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", mibobj.tcp.tcpConnTable.tcpConnLocalAddress.value.clone().get(index).unwrap())); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.tcp.tcpConnTable.tcpConnLocalPort.value.len().cmp(&0)              { std::cmp::Ordering::Greater => { ui.label(mibobj.tcp.tcpConnTable.tcpConnLocalPort.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.tcp.tcpConnTable.tcpConnRemAddress.value.len().cmp(&0)                    { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", mibobj.tcp.tcpConnTable.tcpConnRemAddress.value.clone().get(index).unwrap())); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.tcp.tcpConnTable.tcpConnRemPort.value.len().cmp(&0)                    { std::cmp::Ordering::Greater => { ui.label(mibobj.tcp.tcpConnTable.tcpConnRemPort.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                            });
                                    });
                                });
                            });
                            
                            ui.collapsing(&mibobj.tcp.tcpInErrs.name, |ui| match &mibobj.tcp.tcpInErrs.value.len()     { 1 => ui.label(mibobj.tcp.tcpInErrs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.tcp.tcpOutRsts.name, |ui| match &mibobj.tcp.tcpOutRsts.value.len()     { 1 => ui.label(mibobj.tcp.tcpOutRsts.value.first().unwrap().to_string()), _ => ui.spinner() });
                        });
                        ui.collapsing("Udp", |ui| {
                            ui.collapsing(&mibobj.udp.udpInDatagrams.name, |ui| match &mibobj.udp.udpInDatagrams.value.len()     { 1 => ui.label(mibobj.udp.udpInDatagrams.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.udp.udpNoPorts.name, |ui| match &mibobj.udp.udpNoPorts.value.len()     { 1 => ui.label(mibobj.udp.udpNoPorts.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.udp.udpInErrors.name, |ui| match &mibobj.udp.udpInErrors.value.len()     { 1 => ui.label(mibobj.udp.udpInErrors.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.udp.udpOutDatagrams.name, |ui| match &mibobj.udp.udpOutDatagrams.value.len()     { 1 => ui.label(mibobj.udp.udpOutDatagrams.value.first().unwrap().to_string()), _ => ui.spinner() });
                            
                            ui.collapsing("udpTable", |ui| {
                                egui::ScrollArea::horizontal().auto_shrink(false).show(ui, |ui| {
                                    TableBuilder::new(ui)
                                        .striped(true)
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atIfIndex
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))     // atPhysAddress
                                        .header(26.0, |mut header| {
                                            header.col(|ui| { ui.strong(&mibobj.udp.udpTable.udpLocalAddress.name); });
                                            header.col(|ui| { ui.strong(&mibobj.udp.udpTable.udpLocalPort.name); });
                                        })
                                        .body(|body| {
                                            body.rows(26.0, mibobj.udp.udpTable.udpLocalPort.value.len(), |index, mut row| {
                                                row.col(|ui| match &mibobj.udp.udpTable.udpLocalAddress.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", mibobj.udp.udpTable.udpLocalAddress.value.clone().get(index).unwrap())); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.udp.udpTable.udpLocalPort.value.len().cmp(&0)          { std::cmp::Ordering::Greater => { ui.label(mibobj.udp.udpTable.udpLocalPort.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                            });
                                    });
                                });
                            });
                        });
                        ui.collapsing("Egp", |ui| {
                            ui.collapsing(&mibobj.egp.egpInMsgs.name, |ui| match &mibobj.egp.egpInMsgs.value.len()     { 1 => ui.label(mibobj.egp.egpInMsgs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.egp.egpInErrors.name, |ui| match &mibobj.egp.egpInErrors.value.len()     { 1 => ui.label(mibobj.egp.egpInErrors.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.egp.egpOutMsgs.name, |ui| match &mibobj.egp.egpOutMsgs.value.len()     { 1 => ui.label(mibobj.egp.egpOutMsgs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.egp.egpOutErrors.name, |ui| match &mibobj.egp.egpOutErrors.value.len()     { 1 => ui.label(mibobj.egp.egpOutErrors.value.first().unwrap().to_string()), _ => ui.spinner() });
                            
                            ui.collapsing("TcpConnTable", |ui| {
                                egui::ScrollArea::horizontal().auto_shrink(false).show(ui, |ui| {
                                    TableBuilder::new(ui)
                                        .striped(true)
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true))
                                        .header(26.0, |mut header| {
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighState.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighAddr.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighAs.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighInMsgs.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighInErrs.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighOutMsgs.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighOutErrs.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighInErrMsgs.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighOutErrMsgs.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighStateUps.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighStateDowns.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighIntervalHello.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighIntervalPoll.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighMode.name); });
                                            header.col(|ui| { ui.strong(&mibobj.egp.egpNeighTable.egpNeighEventTrigger.name); });
                                        })
                                        .body(|body| {
                                            body.rows(26.0, mibobj.egp.egpNeighTable.egpNeighState.value.len(), |index, mut row| {
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighState.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighState.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighAddr.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", mibobj.egp.egpNeighTable.egpNeighAddr.value.clone().get(index).unwrap())); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighAs.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighAs.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighInMsgs.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighInMsgs.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighInErrs.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighInErrs.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighOutMsgs.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighOutMsgs.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighOutErrs.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighOutErrs.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighInErrMsgs.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighInErrMsgs.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighOutErrMsgs.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighOutErrMsgs.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighStateUps.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighStateUps.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighStateDowns.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighStateDowns.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighIntervalHello.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighIntervalHello.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighIntervalPoll.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighIntervalPoll.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighMode.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighMode.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                                row.col(|ui| match &mibobj.egp.egpNeighTable.egpNeighEventTrigger.value.len().cmp(&0)                 { std::cmp::Ordering::Greater => { ui.label(mibobj.egp.egpNeighTable.egpNeighEventTrigger.value.clone().get(index).unwrap().to_string()); } _ => { ui.spinner(); } });
                                            });
                                    });
                                });
                            });
                            
                            ui.collapsing(&mibobj.egp.egpAs.name, |ui| match &mibobj.egp.egpAs.value.len()     { 1 => ui.label(mibobj.egp.egpAs.value.first().unwrap().to_string()), _ => ui.spinner() });
                        });
                        ui.collapsing(&mibobj.transmission.name,     |ui| match &mibobj.transmission.value.len()     { 1 => ui.label(format!("{:02x?}", mibobj.transmission.value.first().unwrap())), _ => ui.spinner() });
                        ui.collapsing("Snmp", |ui| {
                            ui.collapsing(&mibobj.snmp.snmpInPkts.name, |ui| match &mibobj.snmp.snmpInPkts.value.len()     { 1 => ui.label(mibobj.snmp.snmpInPkts.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpOutPkts.name, |ui| match &mibobj.snmp.snmpOutPkts.value.len()     { 1 => ui.label(mibobj.snmp.snmpOutPkts.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInBadVersions.name, |ui| match &mibobj.snmp.snmpInBadVersions.value.len()     { 1 => ui.label(mibobj.snmp.snmpInBadVersions.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInBadCommunityNames.name, |ui| match &mibobj.snmp.snmpInBadCommunityNames.value.len()     { 1 => ui.label(mibobj.snmp.snmpInBadCommunityNames.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInBadCommunityUses.name, |ui| match &mibobj.snmp.snmpInBadCommunityUses.value.len()     { 1 => ui.label(mibobj.snmp.snmpInBadCommunityUses.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInASNParseErrs.name, |ui| match &mibobj.snmp.snmpInASNParseErrs.value.len()     { 1 => ui.label(mibobj.snmp.snmpInASNParseErrs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInTooBigs.name, |ui| match &mibobj.snmp.snmpInTooBigs.value.len()     { 1 => ui.label(mibobj.snmp.snmpInTooBigs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInNoSuchNames.name, |ui| match &mibobj.snmp.snmpInNoSuchNames.value.len()     { 1 => ui.label(mibobj.snmp.snmpInNoSuchNames.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInBadValues.name, |ui| match &mibobj.snmp.snmpInBadValues.value.len()     { 1 => ui.label(mibobj.snmp.snmpInBadValues.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInReadOnlys.name, |ui| match &mibobj.snmp.snmpInReadOnlys.value.len()     { 1 => ui.label(mibobj.snmp.snmpInReadOnlys.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInGenErrs.name, |ui| match &mibobj.snmp.snmpInGenErrs.value.len()     { 1 => ui.label(mibobj.snmp.snmpInGenErrs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInTotalReqVars.name, |ui| match &mibobj.snmp.snmpInTotalReqVars.value.len()     { 1 => ui.label(mibobj.snmp.snmpInTotalReqVars.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInTotalSetVars.name, |ui| match &mibobj.snmp.snmpInTotalSetVars.value.len()     { 1 => ui.label(mibobj.snmp.snmpInTotalSetVars.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInGetRequests.name, |ui| match &mibobj.snmp.snmpInGetRequests.value.len()     { 1 => ui.label(mibobj.snmp.snmpInGetRequests.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInGetNexts.name, |ui| match &mibobj.snmp.snmpInGetNexts.value.len()     { 1 => ui.label(mibobj.snmp.snmpInGetNexts.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInSetRequests.name, |ui| match &mibobj.snmp.snmpInSetRequests.value.len()     { 1 => ui.label(mibobj.snmp.snmpInSetRequests.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInGetResponses.name, |ui| match &mibobj.snmp.snmpInGetResponses.value.len()     { 1 => ui.label(mibobj.snmp.snmpInGetResponses.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpInTraps.name, |ui| match &mibobj.snmp.snmpInTraps.value.len()     { 1 => ui.label(mibobj.snmp.snmpInTraps.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpOutTooBigs.name, |ui| match &mibobj.snmp.snmpOutTooBigs.value.len()     { 1 => ui.label(mibobj.snmp.snmpOutTooBigs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpOutNoSuchNames.name, |ui| match &mibobj.snmp.snmpOutNoSuchNames.value.len()     { 1 => ui.label(mibobj.snmp.snmpOutNoSuchNames.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpOutBadValues.name, |ui| match &mibobj.snmp.snmpOutBadValues.value.len()     { 1 => ui.label(mibobj.snmp.snmpOutBadValues.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpOutGenErrs.name, |ui| match &mibobj.snmp.snmpOutGenErrs.value.len()     { 1 => ui.label(mibobj.snmp.snmpOutGenErrs.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpOutGetRequests.name, |ui| match &mibobj.snmp.snmpOutGetRequests.value.len()     { 1 => ui.label(mibobj.snmp.snmpOutGetRequests.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpOutGetNexts.name, |ui| match &mibobj.snmp.snmpOutGetNexts.value.len()     { 1 => ui.label(mibobj.snmp.snmpOutGetNexts.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpOutSetRequests.name, |ui| match &mibobj.snmp.snmpOutSetRequests.value.len()     { 1 => ui.label(mibobj.snmp.snmpOutSetRequests.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpOutGetResponses.name, |ui| match &mibobj.snmp.snmpOutGetResponses.value.len()     { 1 => ui.label(mibobj.snmp.snmpOutGetResponses.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpOutTraps.name, |ui| match &mibobj.snmp.snmpOutTraps.value.len()     { 1 => ui.label(mibobj.snmp.snmpOutTraps.value.first().unwrap().to_string()), _ => ui.spinner() });
                            ui.collapsing(&mibobj.snmp.snmpEnableAuthenTraps.name, |ui| match &mibobj.snmp.snmpEnableAuthenTraps.value.len()     { 1 => ui.label(mibobj.snmp.snmpEnableAuthenTraps.value.first().unwrap().to_string()), _ => ui.spinner() });
                        });
                    });
                });
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("center panel");
                });
            },
            None => {
                egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
                    ui.heading("top panel");
                });
                egui::SidePanel::left("side_panel").show(ctx, |ui| {
                    ui.heading("side panel");
                    ui.label("no objects found");
                    ui.spinner();
                });
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("center panel");
                });
            }
        }
    }
}