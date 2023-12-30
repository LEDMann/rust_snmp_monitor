pub mod MibModule {
    use async_trait::async_trait;
    use chrono::Utc;
    use csnmp::{ObjectIdentifier, Snmp2cClient};
    use egui::{Context, Ui, Window};
    use egui_extras::{Column, TableBuilder};
    use serde::{Deserialize, Serialize};
    use std::{
        fs::File,
        io::{BufRead, BufReader},
        str::FromStr,
    };

    use crate::{Plottable, SnmpMonitorApp};

    #[derive(Serialize, Deserialize)]
    pub struct MibObject {
        pub oid: Vec<u16>,
        pub timestamp: i64,
        pub system: System,
        pub interfaces: Interfaces,
        pub at: At,
        pub ip: Ip,
        pub icmp: Icmp,
        pub tcp: Tcp,
        pub udp: Udp,
        pub egp: Egp,
        pub transmission: MibValue,
        pub snmp: Snmp,
    }

    #[derive(Serialize, Deserialize)]
    pub struct System {
        pub oid: Vec<u16>,
        pub sysDesc: MibValue,
        pub sysObjectID: MibValue,
        pub sysUpTime: MibValue,
        pub sysContact: MibValue,
        pub sysName: MibValue,
        pub sysLocation: MibValue,
        pub sysServices: MibValue,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Interfaces {
        pub oid: Vec<u16>,
        pub ifNumber: MibValue,
        pub ifTable: IfTable,
    }

    #[derive(Serialize, Deserialize)]
    pub struct IfTable {
        pub oid: Vec<u16>,
        pub ifIndex: MibValue,
        pub ifDescr: MibValue,
        pub ifType: MibValue,
        pub ifMtu: MibValue,
        pub ifSpeed: MibValue,
        pub ifPhysAddress: MibValue,
        pub ifAdminStatus: MibValue,
        pub ifOperStatus: MibValue,
        pub ifLastChange: MibValue,
        pub ifInOctets: MibValue,
        pub ifInUcastPkts: MibValue,
        pub ifInNUcastPkts: MibValue,
        pub ifInDiscards: MibValue,
        pub ifInErrors: MibValue,
        pub ifInUnknownProtos: MibValue,
        pub ifOutOctets: MibValue,
        pub ifOutUcastPkts: MibValue,
        pub ifOutNUcastPkts: MibValue,
        pub ifOutDiscards: MibValue,
        pub ifOutErrors: MibValue,
        pub ifOutQLen: MibValue,
        pub ifSpecific: MibValue,
    }

    #[derive(Serialize, Deserialize)]
    pub struct At {
        pub oid: Vec<u16>,
        pub atTable: AtTable,
    }

    #[derive(Serialize, Deserialize)]
    pub struct AtTable {
        pub oid: Vec<u16>,
        pub atIfIndex: MibValue,
        pub atPhysAddress: MibValue,
        pub atNetAddress: MibValue,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Ip {
        pub oid: Vec<u16>,
        pub ipForwarding: MibValue,
        pub ipDefaultTTL: MibValue,
        pub ipInReceives: MibValue,
        pub ipInHdrErrors: MibValue,
        pub ipInAddrErrors: MibValue,
        pub ipForwDatagrams: MibValue,
        pub ipInUnknownProtos: MibValue,
        pub ipInDiscards: MibValue,
        pub ipInDelivers: MibValue,
        pub ipOutRequests: MibValue,
        pub ipOutDiscards: MibValue,
        pub ipOutNoRoutes: MibValue,
        pub ipReasmTimeout: MibValue,
        pub ipReasmReqds: MibValue,
        pub ipReasmOKs: MibValue,
        pub ipReasmFails: MibValue,
        pub ipFragOKs: MibValue,
        pub ipFragFails: MibValue,
        pub ipFragCreates: MibValue,
        pub ipAddrTable: IpAddrTable,
        pub ipRouteTable: IpRouteTable,
        pub ipNetToMediaTable: IpNetToMediaTable,
        pub ipRoutingDiscards: MibValue,
    }

    #[derive(Serialize, Deserialize)]
    pub struct IpAddrTable {
        pub oid: Vec<u16>,
        pub ipAdEntAddr: MibValue,
        pub ipAdEntIfIndex: MibValue,
        pub ipAdEntNetMask: MibValue,
        pub ipAdEntBcastAddr: MibValue,
        pub ipAdEntReasmMaxSize: MibValue,
    }

    #[derive(Serialize, Deserialize)]
    pub struct IpRouteTable {
        pub oid: Vec<u16>,
        pub ipRouteDest: MibValue,
        pub ipRouteIfIndex: MibValue,
        pub ipRouteMetric1: MibValue,
        pub ipRouteMetric2: MibValue,
        pub ipRouteMetric3: MibValue,
        pub ipRouteMetric4: MibValue,
        pub ipRouteNextHop: MibValue,
        pub ipRouteType: MibValue,
        pub ipRouteProto: MibValue,
        pub ipRouteAge: MibValue,
        pub ipRouteMask: MibValue,
        pub ipRouteMetric5: MibValue,
        pub ipRouteInfo: MibValue,
    }

    #[derive(Serialize, Deserialize)]
    pub struct IpNetToMediaTable {
        pub oid: Vec<u16>,
        pub ipNetToMediaIfIndex: MibValue,
        pub ipNetToMediaPhysAddress: MibValue,
        pub ipNetToMediaNetAddress: MibValue,
        pub ipNetToMediaType: MibValue,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Icmp {
        pub oid: Vec<u16>,
        pub icmpInMsgs: MibValue,
        pub icmpInErrors: MibValue,
        pub icmpInDestUnreachs: MibValue,
        pub icmpInTimeExcds: MibValue,
        pub icmpInParmProbs: MibValue,
        pub icmpInSrcQuenchs: MibValue,
        pub icmpInRedirects: MibValue,
        pub icmpInEchos: MibValue,
        pub icmpInEchoReps: MibValue,
        pub icmpInTimestamps: MibValue,
        pub icmpInTimestampReps: MibValue,
        pub icmpInAddrMasks: MibValue,
        pub icmpInAddrMaskReps: MibValue,
        pub icmpOutMsgs: MibValue,
        pub icmpOutErrors: MibValue,
        pub icmpOutDestUnreachs: MibValue,
        pub icmpOutTimeExcds: MibValue,
        pub icmpOutParmProbs: MibValue,
        pub icmpOutSrcQuenchs: MibValue,
        pub icmpOutRedirects: MibValue,
        pub icmpOutEchos: MibValue,
        pub icmpOutEchoReps: MibValue,
        pub icmpOutTimestamps: MibValue,
        pub icmpOutTimestampReps: MibValue,
        pub icmpOutAddrMasks: MibValue,
        pub icmpOutAddrMaskReps: MibValue,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Tcp {
        pub oid: Vec<u16>,
        pub tcpRtoAlgorithm: MibValue,
        pub tcpRtoMin: MibValue,
        pub tcpRtoMax: MibValue,
        pub tcpMaxConn: MibValue,
        pub tcpActiveOpens: MibValue,
        pub tcpPassiveOpens: MibValue,
        pub tcpAttemptFails: MibValue,
        pub tcpEstabResets: MibValue,
        pub tcpCurrEstab: MibValue,
        pub tcpInSegs: MibValue,
        pub tcpOutSegs: MibValue,
        pub tcpRetransSegs: MibValue,
        pub tcpConnTable: TcpConnTable,
        pub tcpInErrs: MibValue,
        pub tcpOutRsts: MibValue,
    }

    #[derive(Serialize, Deserialize)]
    pub struct TcpConnTable {
        pub oid: Vec<u16>,
        pub tcpConnState: MibValue,
        pub tcpConnLocalAddress: MibValue,
        pub tcpConnLocalPort: MibValue,
        pub tcpConnRemAddress: MibValue,
        pub tcpConnRemPort: MibValue,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Udp {
        pub oid: Vec<u16>,
        pub udpInDatagrams: MibValue,
        pub udpNoPorts: MibValue,
        pub udpInErrors: MibValue,
        pub udpOutDatagrams: MibValue,
        pub udpTable: UdpTable,
    }

    #[derive(Serialize, Deserialize)]
    pub struct UdpTable {
        pub oid: Vec<u16>,
        pub udpLocalAddress: MibValue,
        pub udpLocalPort: MibValue,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Egp {
        pub oid: Vec<u16>,
        pub egpInMsgs: MibValue,
        pub egpInErrors: MibValue,
        pub egpOutMsgs: MibValue,
        pub egpOutErrors: MibValue,
        pub egpNeighTable: EgpNeighTable,
        pub egpAs: MibValue,
    }

    #[derive(Serialize, Deserialize)]
    pub struct EgpNeighTable {
        pub oid: Vec<u16>,
        pub egpNeighState: MibValue,
        pub egpNeighAddr: MibValue,
        pub egpNeighAs: MibValue,
        pub egpNeighInMsgs: MibValue,
        pub egpNeighInErrs: MibValue,
        pub egpNeighOutMsgs: MibValue,
        pub egpNeighOutErrs: MibValue,
        pub egpNeighInErrMsgs: MibValue,
        pub egpNeighOutErrMsgs: MibValue,
        pub egpNeighStateUps: MibValue,
        pub egpNeighStateDowns: MibValue,
        pub egpNeighIntervalHello: MibValue,
        pub egpNeighIntervalPoll: MibValue,
        pub egpNeighMode: MibValue,
        pub egpNeighEventTrigger: MibValue,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Snmp {
        pub oid: Vec<u16>,
        pub snmpInPkts: MibValue,
        pub snmpOutPkts: MibValue,
        pub snmpInBadVersions: MibValue,
        pub snmpInBadCommunityNames: MibValue,
        pub snmpInBadCommunityUses: MibValue,
        pub snmpInASNParseErrs: MibValue,
        pub snmpInTooBigs: MibValue,
        pub snmpInNoSuchNames: MibValue,
        pub snmpInBadValues: MibValue,
        pub snmpInReadOnlys: MibValue,
        pub snmpInGenErrs: MibValue,
        pub snmpInTotalReqVars: MibValue,
        pub snmpInTotalSetVars: MibValue,
        pub snmpInGetRequests: MibValue,
        pub snmpInGetNexts: MibValue,
        pub snmpInSetRequests: MibValue,
        pub snmpInGetResponses: MibValue,
        pub snmpInTraps: MibValue,
        pub snmpOutTooBigs: MibValue,
        pub snmpOutNoSuchNames: MibValue,
        pub snmpOutBadValues: MibValue,
        pub snmpOutGenErrs: MibValue,
        pub snmpOutGetRequests: MibValue,
        pub snmpOutGetNexts: MibValue,
        pub snmpOutSetRequests: MibValue,
        pub snmpOutGetResponses: MibValue,
        pub snmpOutTraps: MibValue,
        pub snmpEnableAuthenTraps: MibValue,
    }

    impl MibObject {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            println!("looking in mibobject for oid {:?}[..6] = {:?} vs {:?}", oid, &oid[..6], &self.ip.oid[..]);
            match &oid[..7] {
                oid_slice if oid_slice == &self.system.oid[..] => self.system.find_oid(oid),
                oid_slice if oid_slice == &self.interfaces.oid[..] => self.interfaces.find_oid(oid),
                oid_slice if oid_slice == &self.at.oid[..] => self.at.find_oid(oid),
                oid_slice if oid_slice == &self.ip.oid[..] => self.ip.find_oid(oid),
                oid_slice if oid_slice == &self.icmp.oid[..] => self.icmp.find_oid(oid),
                oid_slice if oid_slice == &self.tcp.oid[..] => self.tcp.find_oid(oid),
                oid_slice if oid_slice == &self.udp.oid[..] => self.udp.find_oid(oid),
                oid_slice if oid_slice == &self.egp.oid[..] => self.egp.find_oid(oid),
                oid_slice if self.transmission.has_oid(oid_slice) => Some(self.transmission.clone()),
                oid_slice if oid_slice == &self.snmp.oid[..] => self.snmp.find_oid(oid),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.system.walk(client).await;
            self.interfaces.walk(client).await;
            self.at.walk(client).await;
            self.ip.walk(client).await;
            self.icmp.walk(client).await;
            self.tcp.walk(client).await;
            self.udp.walk(client).await;
            self.egp.walk(client).await;
            self.transmission.walk(client).await;
            self.snmp.walk(client).await;
        }

        pub fn egui_show(&self, ctx: &egui::Context, app: &mut SnmpMonitorApp) {
            egui::SidePanel::left("side_panel").show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.system.egui_show(app, ctx, ui);
                    self.interfaces.egui_show(app, ctx, ui);
                    self.at.egui_show(app, ctx, ui);
                    self.ip.egui_show(app, ctx, ui);
                    self.icmp.egui_show(app, ctx, ui);
                    self.tcp.egui_show(app, ctx, ui);
                    self.udp.egui_show(app, ctx, ui);
                    self.egp.egui_show(app, ctx, ui);
                    self.transmission.egui_show(app, ctx, ui);
                    self.snmp.egui_show(app, ctx, ui);
                });
            });
        }
    }

    impl System {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..8] {
                oid_slice if self.sysDesc.has_oid(oid_slice) => Some(self.sysDesc.clone()),
                oid_slice if self.sysObjectID.has_oid(oid_slice) => Some(self.sysObjectID.clone()),
                oid_slice if self.sysUpTime.has_oid(oid_slice) => Some(self.sysUpTime.clone()),
                oid_slice if self.sysContact.has_oid(oid_slice) => Some(self.sysContact.clone()),
                oid_slice if self.sysName.has_oid(oid_slice) => Some(self.sysName.clone()),
                oid_slice if self.sysLocation.has_oid(oid_slice) => Some(self.sysLocation.clone()),
                oid_slice if self.sysServices.has_oid(oid_slice) => Some(self.sysServices.clone()),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.sysDesc.walk(client).await;
            self.sysObjectID.walk(client).await;
            self.sysUpTime.walk(client).await;
            self.sysContact.walk(client).await;
            self.sysName.walk(client).await;
            self.sysLocation.walk(client).await;
            self.sysServices.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("System", |ui| {
                self.sysDesc.egui_show(app, ctx, ui);
                self.sysObjectID.egui_show(app, ctx, ui);
                self.sysUpTime.egui_show(app, ctx, ui);
                self.sysContact.egui_show(app, ctx, ui);
                self.sysName.egui_show(app, ctx, ui);
                self.sysLocation.egui_show(app, ctx, ui);
                self.sysServices.egui_show(app, ctx, ui);
            });
        }
    }

    impl Interfaces {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..8] {
                oid_slice if self.ifNumber.has_oid(oid_slice) => Some(self.ifNumber.clone()),
                oid_slice if oid_slice == &self.ifTable.oid[..] => self.ifTable.find_oid(oid),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.ifNumber.walk(client).await;
            self.ifTable.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("Interfaces", |ui| {
                self.ifNumber.egui_show(app, ctx, ui);
                self.ifTable.egui_show(app, ctx, ui);
            });
        }
    }

    impl IfTable {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..10] {
                oid_slice if self.ifIndex.has_oid(oid_slice) => Some(self.ifIndex.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifDescr.has_oid(oid_slice) => Some(self.ifDescr.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifType.has_oid(oid_slice) => Some(self.ifType.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifMtu.has_oid(oid_slice) => Some(self.ifMtu.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifSpeed.has_oid(oid_slice) => Some(self.ifSpeed.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifPhysAddress.has_oid(oid_slice) => Some(self.ifPhysAddress.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifAdminStatus.has_oid(oid_slice) => Some(self.ifAdminStatus.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifOperStatus.has_oid(oid_slice) => Some(self.ifOperStatus.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifLastChange.has_oid(oid_slice) => Some(self.ifLastChange.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifInOctets.has_oid(oid_slice) => Some(self.ifInOctets.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifInUcastPkts.has_oid(oid_slice) => Some(self.ifInUcastPkts.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifInNUcastPkts.has_oid(oid_slice) => Some(self.ifInNUcastPkts.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifInDiscards.has_oid(oid_slice) => Some(self.ifInDiscards.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifInErrors.has_oid(oid_slice) => Some(self.ifInErrors.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifInUnknownProtos.has_oid(oid_slice) => Some(self.ifInUnknownProtos.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifOutOctets.has_oid(oid_slice) => Some(self.ifOutOctets.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifOutUcastPkts.has_oid(oid_slice) => Some(self.ifOutUcastPkts.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifOutNUcastPkts.has_oid(oid_slice) => Some(self.ifOutNUcastPkts.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifOutDiscards.has_oid(oid_slice) => Some(self.ifOutDiscards.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifOutErrors.has_oid(oid_slice) => Some(self.ifOutErrors.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifOutQLen.has_oid(oid_slice) => Some(self.ifOutQLen.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ifSpecific.has_oid(oid_slice) => Some(self.ifSpecific.clone_index(oid.last().unwrap().to_owned() as usize)),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.ifIndex.walk(client).await;
            self.ifDescr.walk(client).await;
            self.ifType.walk(client).await;
            self.ifMtu.walk(client).await;
            self.ifSpeed.walk(client).await;
            self.ifPhysAddress.walk(client).await;
            self.ifAdminStatus.walk(client).await;
            self.ifOperStatus.walk(client).await;
            self.ifLastChange.walk(client).await;
            self.ifInOctets.walk(client).await;
            self.ifInUcastPkts.walk(client).await;
            self.ifInNUcastPkts.walk(client).await;
            self.ifInDiscards.walk(client).await;
            self.ifInErrors.walk(client).await;
            self.ifInUnknownProtos.walk(client).await;
            self.ifOutOctets.walk(client).await;
            self.ifOutUcastPkts.walk(client).await;
            self.ifOutNUcastPkts.walk(client).await;
            self.ifOutDiscards.walk(client).await;
            self.ifOutErrors.walk(client).await;
            self.ifOutQLen.walk(client).await;
            self.ifSpecific.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("ifTable", |ui| {
                if ui.add(egui::Button::new("open table")).clicked() {
                    app.context.open_tabs.insert("ifTable".to_owned());
                    app.tabs_tree
                        .main_surface_mut()
                        .push_to_focused_leaf("ifTable".to_owned());
                }
            });
        }

        pub fn egui_table_show(&self, ui: &mut Ui) {
            egui::ScrollArea::horizontal()
                .auto_shrink(false)
                .show(ui, |ui| {
                    TableBuilder::new(ui)
                        .striped(true)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifIndex
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifDescr
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifType
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifMtu
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifSpeed
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifPhysAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifAdminStatus
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifOperStatus
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifLastChange
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifInOctets
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifInUcastPkts
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifInNUcastPkts
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifInDiscards
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifInErrors
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifInUnknownProtos
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifOutOctets
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifOutUcastPkts
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifOutNUcastPkts
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifOutDiscards
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifOutErrors
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifOutQLen
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // ifSpecific
                        .header(26.0, |mut header| {
                            header.col(|ui| { ui.strong(&self.ifIndex.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifDescr.as_mvstring().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifType.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifMtu.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifSpeed.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifPhysAddress.as_mvipv6().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifAdminStatus.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifOperStatus.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifLastChange.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifInOctets.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifInUcastPkts.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifInNUcastPkts.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifInDiscards.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifInErrors.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifInUnknownProtos.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifOutOctets.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifOutUcastPkts.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifOutNUcastPkts.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifOutDiscards.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifOutErrors.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifOutQLen.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ifSpecific.as_mvoid().unwrap().name); });
                        })
                        .body(|body| {
                            body.rows(26.0, self.ifIndex.as_mvinti32().unwrap().value.len(), |index, mut row| {
                                row.col(|ui| match &self.ifIndex.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifIndex.as_mvinti32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ifDescr.as_mvstring().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifDescr.as_mvstring().unwrap().value.get(index).unwrap());}, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ifType.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifType.as_mvinti32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifMtu.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifMtu.as_mvinti32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifSpeed.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifSpeed.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifPhysAddress.as_mvipv6().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(format!("{:02x?}", self.ifPhysAddress.as_mvipv6().unwrap().value.get(index).unwrap())); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ifAdminStatus.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifAdminStatus.as_mvinti32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifOperStatus.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifOperStatus.as_mvinti32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifLastChange.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifLastChange.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifInOctets.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifInOctets.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifInUcastPkts.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifInUcastPkts.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifInNUcastPkts.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifInNUcastPkts.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifInDiscards.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifInDiscards.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifInErrors.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifInErrors.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifInUnknownProtos.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifInUnknownProtos.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifOutOctets.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifOutOctets.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifOutUcastPkts.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifOutUcastPkts.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifOutNUcastPkts.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifOutNUcastPkts.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifOutDiscards.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifOutDiscards.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifOutErrors.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifOutErrors.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifOutQLen.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifOutQLen.as_mvintu32().unwrap().value.get(index).unwrap().to_string()); }, _ => { ui.spinner(); }});
                                row.col(|ui| match &self.ifSpecific.as_mvoid().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(self.ifSpecific.as_mvoid().unwrap().value.get(index).unwrap().into_iter().map(|b| b.to_string()).collect::<Vec<String>>().join("."),); }, _ => { ui.spinner(); }});
                            });
                        });
                });
        }
    }

    impl At {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..8] {
                oid_slice if oid_slice == &self.atTable.oid[..] => self.atTable.find_oid(oid),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.atTable.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("At", |ui| {
                self.atTable.egui_show(app, ctx, ui);
            });
        }
    }

    impl AtTable {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..10] {
                oid_slice if self.atIfIndex.has_oid(oid_slice) => Some(self.atIfIndex.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.atPhysAddress.has_oid(oid_slice) => Some(self.atPhysAddress.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.atNetAddress.has_oid(oid_slice) => Some(self.atNetAddress.clone_index(oid.last().unwrap().to_owned() as usize)),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.atIfIndex.walk(client).await;
            self.atPhysAddress.walk(client).await;
            self.atNetAddress.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("atTable", |ui| {
                if ui.add(egui::Button::new("open table")).clicked() {
                    app.context.open_tabs.insert("atTable".to_owned());
                    app.tabs_tree
                        .main_surface_mut()
                        .push_to_focused_leaf("atTable".to_owned());
                }
            });
        }

        pub fn egui_table_show(&self, ui: &mut Ui) {
            egui::ScrollArea::horizontal()
                .auto_shrink(false)
                .show(ui, |ui| {
                    TableBuilder::new(ui)
                        .striped(true)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atIfIndex
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atPhysAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .header(26.0, |mut header| {
                            header.col(|ui| { ui.strong(&self.atIfIndex.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.atPhysAddress.as_mvipv6().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.atNetAddress.as_mvipv4().unwrap().name); });
                        })
                        .body(|body| {
                            body.rows(26.0, self.atIfIndex.as_mvinti32().unwrap().value.len(), |index, mut row| {
                                row.col(|ui| match &self.atIfIndex.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.atIfIndex.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.atPhysAddress.as_mvipv6().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(format!("{:02x?}", self.atPhysAddress.as_mvinti32().unwrap().value.clone().get(index).unwrap()));}, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.atNetAddress.as_mvipv4().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", self.atNetAddress.as_mvinti32().unwrap().value.clone().get(index).unwrap()));}, _ => { ui.spinner(); } });
                            });
                        });
                });
        }
    }

    impl Ip {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            println!("looking in ip values for oid {:?}", oid);
            match &oid[..8] {
                oid_slice if self.ipForwarding.has_oid(oid_slice) => Some(self.ipForwarding.clone()),
                oid_slice if self.ipDefaultTTL.has_oid(oid_slice) => Some(self.ipDefaultTTL.clone()),
                oid_slice if self.ipInReceives.has_oid(oid_slice) => Some(self.ipInReceives.clone()),
                oid_slice if self.ipInHdrErrors.has_oid(oid_slice) => Some(self.ipInHdrErrors.clone()),
                oid_slice if self.ipInAddrErrors.has_oid(oid_slice) => Some(self.ipInAddrErrors.clone()),
                oid_slice if self.ipForwDatagrams.has_oid(oid_slice) => Some(self.ipForwDatagrams.clone()),
                oid_slice if self.ipInUnknownProtos.has_oid(oid_slice) => Some(self.ipInUnknownProtos.clone()),
                oid_slice if self.ipInDiscards.has_oid(oid_slice) => Some(self.ipInDiscards.clone()),
                oid_slice if self.ipInDelivers.has_oid(oid_slice) => Some(self.ipInDelivers.clone()),
                oid_slice if self.ipOutRequests.has_oid(oid_slice) => Some(self.ipOutRequests.clone()),
                oid_slice if self.ipOutDiscards.has_oid(oid_slice) => Some(self.ipOutDiscards.clone()),
                oid_slice if self.ipOutNoRoutes.has_oid(oid_slice) => Some(self.ipOutNoRoutes.clone()),
                oid_slice if self.ipReasmTimeout.has_oid(oid_slice) => Some(self.ipReasmTimeout.clone()),
                oid_slice if self.ipReasmReqds.has_oid(oid_slice) => Some(self.ipReasmReqds.clone()),
                oid_slice if self.ipReasmOKs.has_oid(oid_slice) => Some(self.ipReasmOKs.clone()),
                oid_slice if self.ipReasmFails.has_oid(oid_slice) => Some(self.ipReasmFails.clone()),
                oid_slice if self.ipFragOKs.has_oid(oid_slice) => Some(self.ipFragOKs.clone()),
                oid_slice if self.ipFragFails.has_oid(oid_slice) => Some(self.ipFragFails.clone()),
                oid_slice if self.ipFragCreates.has_oid(oid_slice) => Some(self.ipFragCreates.clone()),
                oid_slice if oid_slice == &self.ipAddrTable.oid[..] => self.ipAddrTable.find_oid(oid),
                oid_slice if oid_slice == &self.ipRouteTable.oid[..] => self.ipRouteTable.find_oid(oid),
                oid_slice if oid_slice == &self.ipNetToMediaTable.oid[..] => self.ipNetToMediaTable.find_oid(oid),
                oid_slice if self.ipRoutingDiscards.has_oid(oid_slice) => Some(self.ipRoutingDiscards.clone()),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.ipForwarding.walk(client).await;
            self.ipDefaultTTL.walk(client).await;
            self.ipInReceives.walk(client).await;
            self.ipInHdrErrors.walk(client).await;
            self.ipInAddrErrors.walk(client).await;
            self.ipForwDatagrams.walk(client).await;
            self.ipInUnknownProtos.walk(client).await;
            self.ipInDiscards.walk(client).await;
            self.ipInDelivers.walk(client).await;
            self.ipOutRequests.walk(client).await;
            self.ipOutDiscards.walk(client).await;
            self.ipOutNoRoutes.walk(client).await;
            self.ipReasmTimeout.walk(client).await;
            self.ipReasmReqds.walk(client).await;
            self.ipReasmOKs.walk(client).await;
            self.ipReasmFails.walk(client).await;
            self.ipFragOKs.walk(client).await;
            self.ipFragFails.walk(client).await;
            self.ipFragCreates.walk(client).await;
            self.ipAddrTable.walk(client).await;
            self.ipRouteTable.walk(client).await;
            self.ipNetToMediaTable.walk(client).await;
            self.ipRoutingDiscards.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("Ip", |ui| {
                self.ipForwarding.egui_show(app, ctx, ui);
                self.ipDefaultTTL.egui_show(app, ctx, ui);
                self.ipInReceives.egui_show(app, ctx, ui);
                self.ipInHdrErrors.egui_show(app, ctx, ui);
                self.ipInAddrErrors.egui_show(app, ctx, ui);
                self.ipForwDatagrams.egui_show(app, ctx, ui);
                self.ipInUnknownProtos.egui_show(app, ctx, ui);
                self.ipInDiscards.egui_show(app, ctx, ui);
                self.ipInDelivers.egui_show(app, ctx, ui);
                self.ipOutRequests.egui_show(app, ctx, ui);
                self.ipOutDiscards.egui_show(app, ctx, ui);
                self.ipOutNoRoutes.egui_show(app, ctx, ui);
                self.ipReasmTimeout.egui_show(app, ctx, ui);
                self.ipReasmReqds.egui_show(app, ctx, ui);
                self.ipReasmOKs.egui_show(app, ctx, ui);
                self.ipReasmFails.egui_show(app, ctx, ui);
                self.ipFragOKs.egui_show(app, ctx, ui);
                self.ipFragFails.egui_show(app, ctx, ui);
                self.ipFragCreates.egui_show(app, ctx, ui);
                self.ipAddrTable.egui_show(app, ctx, ui);
                self.ipRouteTable.egui_show(app, ctx, ui);
                self.ipNetToMediaTable.egui_show(app, ctx, ui);
                self.ipRoutingDiscards.egui_show(app, ctx, ui);
            });
        }
    }

    impl IpAddrTable {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..10] {
                oid_slice if self.ipAdEntAddr.has_oid(oid_slice) => Some(self.ipAdEntAddr.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipAdEntIfIndex.has_oid(oid_slice) => Some(self.ipAdEntIfIndex.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipAdEntNetMask.has_oid(oid_slice) => Some(self.ipAdEntNetMask.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipAdEntBcastAddr.has_oid(oid_slice) => Some(self.ipAdEntBcastAddr.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipAdEntReasmMaxSize.has_oid(oid_slice) => Some(self.ipAdEntReasmMaxSize.clone_index(oid.last().unwrap().to_owned() as usize)),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.ipAdEntAddr.walk(client).await;
            self.ipAdEntIfIndex.walk(client).await;
            self.ipAdEntNetMask.walk(client).await;
            self.ipAdEntBcastAddr.walk(client).await;
            self.ipAdEntReasmMaxSize.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("ipAddrTable", |ui| {
                if ui.add(egui::Button::new("open table")).clicked() {
                    app.context.open_tabs.insert("ipAddrTable".to_owned());
                    app.tabs_tree.main_surface_mut().push_to_focused_leaf("ipAddrTable".to_owned());
                }
            });
        }

        pub fn egui_table_show(&self, ui: &mut Ui) {
            egui::ScrollArea::horizontal()
                .auto_shrink(false)
                .show(ui, |ui| {
                    TableBuilder::new(ui)
                        .striped(true)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atIfIndex
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atPhysAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .header(26.0, |mut header| {
                            header.col(|ui| { ui.strong(&self.ipAdEntAddr.as_mvipv4().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipAdEntIfIndex.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipAdEntNetMask.as_mvipv4().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipAdEntBcastAddr.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipAdEntReasmMaxSize.as_mvinti32().unwrap().name); });
                        })
                        .body(|body| {
                            body.rows(26.0, self.ipAdEntAddr.as_mvipv4().unwrap().value.len(), |index, mut row| {
                                row.col(|ui| match &self.ipAdEntAddr.as_mvipv4().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(format!("{:?}",self.ipAdEntAddr.as_mvipv4().unwrap().value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipAdEntIfIndex.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipAdEntIfIndex.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipAdEntNetMask.as_mvipv4().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(format!("{:?}",self.ipAdEntNetMask.as_mvipv4().unwrap().value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipAdEntBcastAddr.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipAdEntBcastAddr.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipAdEntReasmMaxSize.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipAdEntReasmMaxSize.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                            });
                        });
                });
        }
    }

    impl IpRouteTable {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..10] {
                oid_slice if self.ipRouteDest.has_oid(oid_slice) => Some(self.ipRouteDest.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipRouteIfIndex.has_oid(oid_slice) => Some(self.ipRouteIfIndex.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipRouteMetric1.has_oid(oid_slice) => Some(self.ipRouteMetric1.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipRouteMetric2.has_oid(oid_slice) => Some(self.ipRouteMetric2.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipRouteMetric3.has_oid(oid_slice) => Some(self.ipRouteMetric3.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipRouteMetric4.has_oid(oid_slice) => Some(self.ipRouteMetric4.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipRouteNextHop.has_oid(oid_slice) => Some(self.ipRouteNextHop.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipRouteType.has_oid(oid_slice) => Some(self.ipRouteType.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipRouteProto.has_oid(oid_slice) => Some(self.ipRouteProto.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipRouteAge.has_oid(oid_slice) => Some(self.ipRouteAge.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipRouteMask.has_oid(oid_slice) => Some(self.ipRouteMask.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipRouteMetric5.has_oid(oid_slice) => Some(self.ipRouteMetric5.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipRouteInfo.has_oid(oid_slice) => Some(self.ipRouteInfo.clone_index(oid.last().unwrap().to_owned() as usize)),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.ipRouteDest.walk(client).await;
            self.ipRouteIfIndex.walk(client).await;
            self.ipRouteMetric1.walk(client).await;
            self.ipRouteMetric2.walk(client).await;
            self.ipRouteMetric3.walk(client).await;
            self.ipRouteMetric4.walk(client).await;
            self.ipRouteNextHop.walk(client).await;
            self.ipRouteType.walk(client).await;
            self.ipRouteProto.walk(client).await;
            self.ipRouteAge.walk(client).await;
            self.ipRouteMask.walk(client).await;
            self.ipRouteMetric5.walk(client).await;
            self.ipRouteInfo.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("ipRouteTable", |ui| {
                if ui.add(egui::Button::new("open table")).clicked() {
                    app.context.open_tabs.insert("ipRouteTable".to_owned());
                    app.tabs_tree
                        .main_surface_mut()
                        .push_to_focused_leaf("ipRouteTable".to_owned());
                }
            });
        }

        pub fn egui_table_show(&self, ui: &mut Ui) {
            egui::ScrollArea::horizontal()
                .auto_shrink(false)
                .show(ui, |ui| {
                    TableBuilder::new(ui)
                        .striped(true)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atIfIndex
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atPhysAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true)) // atNetAddress
                        .header(26.0, |mut header| {
                            header.col(|ui| { ui.strong(&self.ipRouteDest.as_mvipv4().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipRouteIfIndex.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipRouteMetric1.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipRouteMetric2.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipRouteMetric3.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipRouteMetric4.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipRouteNextHop.as_mvipv4().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipRouteType.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipRouteProto.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipRouteAge.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipRouteMask.as_mvipv4().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipRouteMetric5.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipRouteInfo.as_mvoid().unwrap().name); });
                        })
                        .body(|body| {
                            body.rows(26.0, self.ipRouteIfIndex.as_mvipv4().unwrap().value.len(), |index, mut row| {
                                row.col(|ui| match &self.ipRouteDest.as_mvipv4().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", self.ipRouteDest.as_mvipv4().unwrap().value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipRouteIfIndex.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipRouteIfIndex.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipRouteMetric1.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipRouteMetric1.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipRouteMetric2.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipRouteMetric2.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipRouteMetric3.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipRouteMetric3.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipRouteMetric4.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipRouteMetric4.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipRouteNextHop.as_mvipv4().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", self.ipRouteNextHop.as_mvipv4().unwrap().value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipRouteType.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipRouteType.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipRouteProto.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipRouteProto.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipRouteAge.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipRouteAge.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipRouteMask.as_mvipv4().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", self.ipRouteMask.as_mvipv4().unwrap().value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipRouteMetric5.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipRouteMetric5.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.ipRouteInfo.as_mvoid().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(format!("{:02x?}", self.ipRouteInfo.as_mvoid().unwrap().value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } });
                            });
                        });
                });
        }
    }

    impl IpNetToMediaTable {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..10] {
                oid_slice if self.ipNetToMediaIfIndex.has_oid(oid_slice) => Some(self.ipNetToMediaIfIndex.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipNetToMediaPhysAddress.has_oid(oid_slice) => Some(self.ipNetToMediaPhysAddress.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipNetToMediaNetAddress.has_oid(oid_slice) => Some(self.ipNetToMediaNetAddress.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.ipNetToMediaType.has_oid(oid_slice) => Some(self.ipNetToMediaType.clone_index(oid.last().unwrap().to_owned() as usize)),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.ipNetToMediaIfIndex.walk(client).await;
            self.ipNetToMediaPhysAddress.walk(client).await;
            self.ipNetToMediaNetAddress.walk(client).await;
            self.ipNetToMediaType.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("ipNetToMediaTable", |ui| {
                if ui.add(egui::Button::new("open table")).clicked() {
                    app.context.open_tabs.insert("ipNetToMediaTable".to_owned());
                    app.tabs_tree
                        .main_surface_mut()
                        .push_to_focused_leaf("ipNetToMediaTable".to_owned());
                }
            });
        }

        pub fn egui_table_show(&self, ui: &mut Ui) {
            egui::ScrollArea::horizontal()
                .auto_shrink(false)
                .show(ui, |ui| {
                    TableBuilder::new(ui)
                        .striped(true)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),) // atIfIndex
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),) // atPhysAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),) // atNetAddress
                        .header(26.0, |mut header| {
                            header.col(|ui| { ui.strong(&self.ipNetToMediaIfIndex.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipNetToMediaPhysAddress.as_mvipv6().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipNetToMediaNetAddress.as_mvipv4().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.ipNetToMediaType.as_mvinti32().unwrap().name); });
                        })
                        .body(|body| {
                            body.rows(26.0, self.ipNetToMediaIfIndex.as_mvinti32().unwrap().value.len(), |index, mut row| {
                                    row.col(|ui| { match &self.ipNetToMediaIfIndex.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipNetToMediaIfIndex.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } }});
                                    row.col(|ui| { match &self.ipNetToMediaPhysAddress.as_mvipv6().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(format!("{:02x?}", self.ipNetToMediaPhysAddress.as_mvipv6().unwrap().value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } } });
                                    row.col(|ui| { match &self.ipNetToMediaNetAddress.as_mvipv4().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => {ui.label(format!("{:?}", self.ipNetToMediaNetAddress.as_mvipv4().unwrap().value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } } });
                                    row.col(|ui| { match &self.ipNetToMediaType.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.ipNetToMediaType.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } }});
                                },
                            );
                        });
                });
        }
    }

    impl Icmp {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..8] {
                oid_slice if self.icmpInMsgs.has_oid(oid_slice) => Some(self.icmpInMsgs.clone()),
                oid_slice if self.icmpInErrors.has_oid(oid_slice) => Some(self.icmpInErrors.clone()),
                oid_slice if self.icmpInDestUnreachs.has_oid(oid_slice) => Some(self.icmpInDestUnreachs.clone()), 
                oid_slice if self.icmpInTimeExcds.has_oid(oid_slice) => Some(self.icmpInTimeExcds.clone()), 
                oid_slice if self.icmpInParmProbs.has_oid(oid_slice) => Some(self.icmpInParmProbs.clone()), 
                oid_slice if self.icmpInSrcQuenchs.has_oid(oid_slice) => Some(self.icmpInSrcQuenchs.clone()), 
                oid_slice if self.icmpInRedirects.has_oid(oid_slice) => Some(self.icmpInRedirects.clone()), 
                oid_slice if self.icmpInEchos.has_oid(oid_slice) => Some(self.icmpInEchos.clone()),
                oid_slice if self.icmpInEchoReps.has_oid(oid_slice) => Some(self.icmpInEchoReps.clone()), 
                oid_slice if self.icmpInTimestamps.has_oid(oid_slice) => Some(self.icmpInTimestamps.clone()), 
                oid_slice if self.icmpInTimestampReps.has_oid(oid_slice) => Some(self.icmpInTimestampReps.clone()), 
                oid_slice if self.icmpInAddrMasks.has_oid(oid_slice) => Some(self.icmpInAddrMasks.clone()), 
                oid_slice if self.icmpInAddrMaskReps.has_oid(oid_slice) => Some(self.icmpInAddrMaskReps.clone()), 
                oid_slice if self.icmpOutMsgs.has_oid(oid_slice) => Some(self.icmpOutMsgs.clone()),
                oid_slice if self.icmpOutErrors.has_oid(oid_slice) => Some(self.icmpOutErrors.clone()), 
                oid_slice if self.icmpOutDestUnreachs.has_oid(oid_slice) => Some(self.icmpOutDestUnreachs.clone()), 
                oid_slice if self.icmpOutTimeExcds.has_oid(oid_slice) => Some(self.icmpOutTimeExcds.clone()), 
                oid_slice if self.icmpOutParmProbs.has_oid(oid_slice) => Some(self.icmpOutParmProbs.clone()), 
                oid_slice if self.icmpOutSrcQuenchs.has_oid(oid_slice) => Some(self.icmpOutSrcQuenchs.clone()), 
                oid_slice if self.icmpOutRedirects.has_oid(oid_slice) => Some(self.icmpOutRedirects.clone()), 
                oid_slice if self.icmpOutEchos.has_oid(oid_slice) => Some(self.icmpOutEchos.clone()),
                oid_slice if self.icmpOutEchoReps.has_oid(oid_slice) => Some(self.icmpOutEchoReps.clone()), 
                oid_slice if self.icmpOutTimestamps.has_oid(oid_slice) => Some(self.icmpOutTimestamps.clone()), 
                oid_slice if self.icmpOutTimestampReps.has_oid(oid_slice) => Some(self.icmpOutTimestampReps.clone()), 
                oid_slice if self.icmpOutAddrMasks.has_oid(oid_slice) => Some(self.icmpOutAddrMasks.clone()), 
                oid_slice if self.icmpOutAddrMaskReps.has_oid(oid_slice) => Some(self.icmpOutAddrMaskReps.clone()), 
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.icmpInMsgs.walk(client).await;
            self.icmpInErrors.walk(client).await;
            self.icmpInDestUnreachs.walk(client).await;
            self.icmpInTimeExcds.walk(client).await;
            self.icmpInParmProbs.walk(client).await;
            self.icmpInSrcQuenchs.walk(client).await;
            self.icmpInRedirects.walk(client).await;
            self.icmpInEchos.walk(client).await;
            self.icmpInEchoReps.walk(client).await;
            self.icmpInTimestamps.walk(client).await;
            self.icmpInTimestampReps.walk(client).await;
            self.icmpInAddrMasks.walk(client).await;
            self.icmpInAddrMaskReps.walk(client).await;
            self.icmpOutMsgs.walk(client).await;
            self.icmpOutErrors.walk(client).await;
            self.icmpOutDestUnreachs.walk(client).await;
            self.icmpOutTimeExcds.walk(client).await;
            self.icmpOutParmProbs.walk(client).await;
            self.icmpOutSrcQuenchs.walk(client).await;
            self.icmpOutRedirects.walk(client).await;
            self.icmpOutEchos.walk(client).await;
            self.icmpOutEchoReps.walk(client).await;
            self.icmpOutTimestamps.walk(client).await;
            self.icmpOutTimestampReps.walk(client).await;
            self.icmpOutAddrMasks.walk(client).await;
            self.icmpOutAddrMaskReps.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("Icmp", |ui| {
                self.icmpInMsgs.egui_show(app, ctx, ui);
                self.icmpInErrors.egui_show(app, ctx, ui);
                self.icmpInDestUnreachs.egui_show(app, ctx, ui);
                self.icmpInTimeExcds.egui_show(app, ctx, ui);
                self.icmpInParmProbs.egui_show(app, ctx, ui);
                self.icmpInSrcQuenchs.egui_show(app, ctx, ui);
                self.icmpInRedirects.egui_show(app, ctx, ui);
                self.icmpInEchos.egui_show(app, ctx, ui);
                self.icmpInEchoReps.egui_show(app, ctx, ui);
                self.icmpInTimestamps.egui_show(app, ctx, ui);
                self.icmpInTimestampReps.egui_show(app, ctx, ui);
                self.icmpInAddrMasks.egui_show(app, ctx, ui);
                self.icmpInAddrMaskReps.egui_show(app, ctx, ui);
                self.icmpOutMsgs.egui_show(app, ctx, ui);
                self.icmpOutErrors.egui_show(app, ctx, ui);
                self.icmpOutDestUnreachs.egui_show(app, ctx, ui);
                self.icmpOutTimeExcds.egui_show(app, ctx, ui);
                self.icmpOutParmProbs.egui_show(app, ctx, ui);
                self.icmpOutSrcQuenchs.egui_show(app, ctx, ui);
                self.icmpOutRedirects.egui_show(app, ctx, ui);
                self.icmpOutEchos.egui_show(app, ctx, ui);
                self.icmpOutEchoReps.egui_show(app, ctx, ui);
                self.icmpOutTimestamps.egui_show(app, ctx, ui);
                self.icmpOutTimestampReps.egui_show(app, ctx, ui);
                self.icmpOutAddrMasks.egui_show(app, ctx, ui);
                self.icmpOutAddrMaskReps.egui_show(app, ctx, ui);
            });
        }
    }

    impl Tcp {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..8] {
                oid_slice if self.tcpRtoAlgorithm.has_oid(oid_slice) => Some(self.tcpRtoAlgorithm.clone()), 
                oid_slice if self.tcpRtoMin.has_oid(oid_slice) => Some(self.tcpRtoMin.clone()),
                oid_slice if self.tcpRtoMax.has_oid(oid_slice) => Some(self.tcpRtoMax.clone()),
                oid_slice if self.tcpMaxConn.has_oid(oid_slice) => Some(self.tcpMaxConn.clone()),
                oid_slice if self.tcpActiveOpens.has_oid(oid_slice) => Some(self.tcpActiveOpens.clone()), 
                oid_slice if self.tcpPassiveOpens.has_oid(oid_slice) => Some(self.tcpPassiveOpens.clone()), 
                oid_slice if self.tcpAttemptFails.has_oid(oid_slice) => Some(self.tcpAttemptFails.clone()), 
                oid_slice if self.tcpEstabResets.has_oid(oid_slice) => Some(self.tcpEstabResets.clone()), 
                oid_slice if self.tcpCurrEstab.has_oid(oid_slice) => Some(self.tcpCurrEstab.clone()),
                oid_slice if self.tcpInSegs.has_oid(oid_slice) => Some(self.tcpInSegs.clone()),
                oid_slice if self.tcpOutSegs.has_oid(oid_slice) => Some(self.tcpOutSegs.clone()),
                oid_slice if self.tcpRetransSegs.has_oid(oid_slice) => Some(self.tcpRetransSegs.clone()), 
                oid_slice if oid_slice == &self.tcpConnTable.oid[..] => self.tcpConnTable.find_oid(oid),
                oid_slice if self.tcpInErrs.has_oid(oid_slice) => Some(self.tcpInErrs.clone()),
                oid_slice if self.tcpOutRsts.has_oid(oid_slice) => Some(self.tcpOutRsts.clone()),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.tcpRtoAlgorithm.walk(client).await;
            self.tcpRtoMin.walk(client).await;
            self.tcpRtoMax.walk(client).await;
            self.tcpMaxConn.walk(client).await;
            self.tcpActiveOpens.walk(client).await;
            self.tcpPassiveOpens.walk(client).await;
            self.tcpAttemptFails.walk(client).await;
            self.tcpEstabResets.walk(client).await;
            self.tcpCurrEstab.walk(client).await;
            self.tcpInSegs.walk(client).await;
            self.tcpOutSegs.walk(client).await;
            self.tcpRetransSegs.walk(client).await;
            self.tcpConnTable.walk(client).await;
            self.tcpInErrs.walk(client).await;
            self.tcpOutRsts.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("Tcp", |ui| {
                self.tcpRtoAlgorithm.egui_show(app, ctx, ui);
                self.tcpRtoMin.egui_show(app, ctx, ui);
                self.tcpRtoMax.egui_show(app, ctx, ui);
                self.tcpMaxConn.egui_show(app, ctx, ui);
                self.tcpActiveOpens.egui_show(app, ctx, ui);
                self.tcpPassiveOpens.egui_show(app, ctx, ui);
                self.tcpAttemptFails.egui_show(app, ctx, ui);
                self.tcpEstabResets.egui_show(app, ctx, ui);
                self.tcpCurrEstab.egui_show(app, ctx, ui);
                self.tcpInSegs.egui_show(app, ctx, ui);
                self.tcpOutSegs.egui_show(app, ctx, ui);
                self.tcpRetransSegs.egui_show(app, ctx, ui);
                self.tcpConnTable.egui_show(app, ctx, ui);
                self.tcpInErrs.egui_show(app, ctx, ui);
                self.tcpOutRsts.egui_show(app, ctx, ui);
            });
        }
    }

    impl TcpConnTable {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..10] {
                oid_slice if self.tcpConnState.has_oid(oid_slice) => Some(self.tcpConnState.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.tcpConnLocalAddress.has_oid(oid_slice) => Some(self.tcpConnLocalAddress.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.tcpConnLocalPort.has_oid(oid_slice) => Some(self.tcpConnLocalPort.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.tcpConnRemAddress.has_oid(oid_slice) => Some(self.tcpConnRemAddress.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.tcpConnRemPort.has_oid(oid_slice) => Some(self.tcpConnRemPort.clone_index(oid.last().unwrap().to_owned() as usize)),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.tcpConnState.walk(client).await;
            self.tcpConnLocalAddress.walk(client).await;
            self.tcpConnLocalPort.walk(client).await;
            self.tcpConnRemAddress.walk(client).await;
            self.tcpConnRemPort.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("tcpConnTable", |ui| {
                if ui.add(egui::Button::new("open table")).clicked() {
                    app.context.open_tabs.insert("tcpConnTable".to_owned());
                    app.tabs_tree
                        .main_surface_mut()
                        .push_to_focused_leaf("tcpConnTable".to_owned());
                }
            });
        }

        pub fn egui_table_show(&self, ui: &mut Ui) {
            egui::ScrollArea::horizontal()
                .auto_shrink(false)
                .show(ui, |ui| {
                    TableBuilder::new(ui)
                        .striped(true)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),) // atIfIndex
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),) // atPhysAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),) // atNetAddress
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),) // atNetAddress
                        .header(26.0, |mut header| {
                            header.col(|ui| { ui.strong(&self.tcpConnState.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.tcpConnLocalAddress.as_mvipv4().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.tcpConnLocalPort.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.tcpConnRemAddress.as_mvipv4().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.tcpConnRemPort.as_mvinti32().unwrap().name); });
                        })
                        .body(|body| {
                            body.rows(26.0, self.tcpConnState.as_mvinti32().unwrap().value.len(), |index, mut row| {
                                row.col(|ui| match &self.tcpConnState.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.tcpConnState.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.tcpConnLocalAddress.as_mvipv4().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", self.tcpConnLocalAddress.as_mvipv4().unwrap().value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.tcpConnLocalPort.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.tcpConnLocalPort.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.tcpConnRemAddress.as_mvipv4().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", self.tcpConnRemAddress.as_mvipv4().unwrap().value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.tcpConnRemPort.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.tcpConnRemPort.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                            });
                        });
                });
        }
    }

    impl Udp {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..8] {
                oid_slice if self.udpInDatagrams.has_oid(oid_slice) => Some(self.udpInDatagrams.clone()), 
                oid_slice if self.udpNoPorts.has_oid(oid_slice) => Some(self.udpNoPorts.clone()),
                oid_slice if self.udpInErrors.has_oid(oid_slice) => Some(self.udpInErrors.clone()),
                oid_slice if self.udpOutDatagrams.has_oid(oid_slice) => Some(self.udpOutDatagrams.clone()), 
                oid_slice if oid_slice == &self.udpTable.oid[..] => self.udpTable.find_oid(oid),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.udpInDatagrams.walk(client).await;
            self.udpNoPorts.walk(client).await;
            self.udpInErrors.walk(client).await;
            self.udpOutDatagrams.walk(client).await;
            self.udpTable.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("Udp", |ui| {
                self.udpInDatagrams.egui_show(app, ctx, ui);
                self.udpNoPorts.egui_show(app, ctx, ui);
                self.udpInErrors.egui_show(app, ctx, ui);
                self.udpOutDatagrams.egui_show(app, ctx, ui);
                self.udpTable.egui_show(app, ctx, ui);
            });
        }
    }

    impl UdpTable {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..10] {
                oid_slice if self.udpLocalAddress.has_oid(oid_slice) => Some(self.udpLocalAddress.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.udpLocalPort.has_oid(oid_slice) => Some(self.udpLocalPort.clone_index(oid.last().unwrap().to_owned() as usize)),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.udpLocalAddress.walk(client).await;
            self.udpLocalPort.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("udpTable", |ui| {
                if ui.add(egui::Button::new("open table")).clicked() {
                    app.context.open_tabs.insert("udpTable".to_owned());
                    app.tabs_tree
                        .main_surface_mut()
                        .push_to_focused_leaf("udpTable".to_owned());
                }
            });
        }

        pub fn egui_table_show(&self, ui: &mut Ui) {
            egui::ScrollArea::horizontal()
                .auto_shrink(false)
                .show(ui, |ui| {
                    TableBuilder::new(ui)
                        .striped(true)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),) // atIfIndex
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),) // atPhysAddress
                        .header(26.0, |mut header| {
                            header.col(|ui| { ui.strong(&self.udpLocalAddress.as_mvipv4().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.udpLocalPort.as_mvinti32().unwrap().name); });
                        })
                        .body(|body| {
                            body.rows(26.0, self.udpLocalPort.as_mvipv4().unwrap().value.len(), |index, mut row| {
                                row.col(|ui| match &self.udpLocalAddress.as_mvipv4().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", self.udpLocalAddress.as_mvipv4().unwrap().value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.udpLocalPort.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.udpLocalPort.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                            });
                        });
                });
        }
    }

    impl Egp {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..8] {
                oid_slice if self.egpInMsgs.has_oid(oid_slice) => Some(self.egpInMsgs.clone()),
                oid_slice if self.egpInErrors.has_oid(oid_slice) => Some(self.egpInErrors.clone()),
                oid_slice if self.egpOutMsgs.has_oid(oid_slice) => Some(self.egpOutMsgs.clone()),
                oid_slice if self.egpOutErrors.has_oid(oid_slice) => Some(self.egpOutErrors.clone()),
                oid_slice if oid_slice == &self.egpNeighTable.oid[..] => self.egpNeighTable.find_oid(oid),
                oid_slice if self.egpAs.has_oid(oid_slice) => Some(self.egpAs.clone()),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.egpInMsgs.walk(client).await;
            self.egpInErrors.walk(client).await;
            self.egpOutMsgs.walk(client).await;
            self.egpOutErrors.walk(client).await;
            self.egpNeighTable.walk(client).await;
            self.egpAs.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("Egp", |ui| {
                self.egpInMsgs.egui_show(app, ctx, ui);
                self.egpInErrors.egui_show(app, ctx, ui);
                self.egpOutMsgs.egui_show(app, ctx, ui);
                self.egpOutErrors.egui_show(app, ctx, ui);
                self.egpNeighTable.egui_show(app, ctx, ui);
                self.egpAs.egui_show(app, ctx, ui);
            });
        }
    }

    impl EgpNeighTable {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..10] {
                oid_slice if self.egpNeighState.has_oid(oid_slice) => Some(self.egpNeighState.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighAddr.has_oid(oid_slice) => Some(self.egpNeighAddr.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighAs.has_oid(oid_slice) => Some(self.egpNeighAs.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighInMsgs.has_oid(oid_slice) => Some(self.egpNeighInMsgs.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighInErrs.has_oid(oid_slice) => Some(self.egpNeighInErrs.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighOutMsgs.has_oid(oid_slice) => Some(self.egpNeighOutMsgs.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighOutErrs.has_oid(oid_slice) => Some(self.egpNeighOutErrs.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighInErrMsgs.has_oid(oid_slice) => Some(self.egpNeighInErrMsgs.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighOutErrMsgs.has_oid(oid_slice) => Some(self.egpNeighOutErrMsgs.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighStateUps.has_oid(oid_slice) => Some(self.egpNeighStateUps.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighStateDowns.has_oid(oid_slice) => Some(self.egpNeighStateDowns.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighIntervalHello.has_oid(oid_slice) => Some(self.egpNeighIntervalHello.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighIntervalPoll.has_oid(oid_slice) => Some(self.egpNeighIntervalPoll.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighMode.has_oid(oid_slice) => Some(self.egpNeighMode.clone_index(oid.last().unwrap().to_owned() as usize)),
                oid_slice if self.egpNeighEventTrigger.has_oid(oid_slice) => Some(self.egpNeighEventTrigger.clone_index(oid.last().unwrap().to_owned() as usize)),
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.egpNeighState.walk(client).await;
            self.egpNeighAddr.walk(client).await;
            self.egpNeighAs.walk(client).await;
            self.egpNeighInMsgs.walk(client).await;
            self.egpNeighInErrs.walk(client).await;
            self.egpNeighOutMsgs.walk(client).await;
            self.egpNeighOutErrs.walk(client).await;
            self.egpNeighInErrMsgs.walk(client).await;
            self.egpNeighOutErrMsgs.walk(client).await;
            self.egpNeighStateUps.walk(client).await;
            self.egpNeighStateDowns.walk(client).await;
            self.egpNeighIntervalHello.walk(client).await;
            self.egpNeighIntervalPoll.walk(client).await;
            self.egpNeighMode.walk(client).await;
            self.egpNeighEventTrigger.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("egpNeighTable", |ui| {
                if ui.add(egui::Button::new("open table")).clicked() {
                    app.context.open_tabs.insert("egpNeighTable".to_owned());
                    app.tabs_tree
                        .main_surface_mut()
                        .push_to_focused_leaf("egpNeighTable".to_owned());
                }
            });
        }

        pub fn egui_table_show(&self, ui: &mut Ui) {
            egui::ScrollArea::horizontal()
                .auto_shrink(false)
                .show(ui, |ui| {
                    TableBuilder::new(ui)
                        .striped(true)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .column(Column::auto_with_initial_suggestion(100.0).at_least(50.0).resizable(true),)
                        .header(26.0, |mut header| {
                            header.col(|ui| { ui.strong(&self.egpNeighState.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighAddr.as_mvipv4().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighAs.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighInMsgs.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighInErrs.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighOutMsgs.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighOutErrs.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighInErrMsgs.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighOutErrMsgs.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighStateUps.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighStateDowns.as_mvintu32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighIntervalHello.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighIntervalPoll.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighMode.as_mvinti32().unwrap().name); });
                            header.col(|ui| { ui.strong(&self.egpNeighEventTrigger.as_mvinti32().unwrap().name); });
                        })
                        .body(|body| {
                            body.rows(26.0, self.egpNeighState.as_mvinti32().unwrap().value.len(), |index, mut row| {
                                row.col(|ui| match &self.egpNeighState.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighState.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighAddr.as_mvipv4().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(format!("{:?}", self.egpNeighAddr.as_mvipv4().unwrap().value.clone().get(index).unwrap())); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighAs.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighAs.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighInMsgs.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighInMsgs.as_mvintu32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighInErrs.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighInErrs.as_mvintu32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighOutMsgs.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighOutMsgs.as_mvintu32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighOutErrs.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighOutErrs.as_mvintu32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighInErrMsgs.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighInErrMsgs.as_mvintu32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighOutErrMsgs.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighOutErrMsgs.as_mvintu32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighStateUps.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighStateUps.as_mvintu32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighStateDowns.as_mvintu32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighStateDowns.as_mvintu32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighIntervalHello.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighIntervalHello.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighIntervalPoll.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighIntervalPoll.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighMode.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighMode.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                                row.col(|ui| match &self.egpNeighEventTrigger.as_mvinti32().unwrap().value.len().cmp(&0) { std::cmp::Ordering::Greater => { ui.label(self.egpNeighEventTrigger.as_mvinti32().unwrap().value.clone().get(index).unwrap().to_string()); }, _ => { ui.spinner(); } });
                            });
                        });
                });
        }
    }

    impl Snmp {
        pub fn find_oid(&self, oid: Vec<u16>) -> Option<MibValue> {
            match &oid[..8] {
                oid_slice if self.snmpInPkts.has_oid(oid_slice) => Some(self.snmpInPkts.clone()),
                oid_slice if self.snmpOutPkts.has_oid(oid_slice) => Some(self.snmpOutPkts.clone()),
                oid_slice if self.snmpInBadVersions.has_oid(oid_slice) => Some(self.snmpInBadVersions.clone()), 
                oid_slice if self.snmpInBadCommunityNames.has_oid(oid_slice) => Some(self.snmpInBadCommunityNames.clone()), 
                oid_slice if self.snmpInBadCommunityUses.has_oid(oid_slice) => Some(self.snmpInBadCommunityUses.clone()), 
                oid_slice if self.snmpInASNParseErrs.has_oid(oid_slice) => Some(self.snmpInASNParseErrs.clone()), 
                oid_slice if self.snmpInTooBigs.has_oid(oid_slice) => Some(self.snmpInTooBigs.clone()), 
                oid_slice if self.snmpInNoSuchNames.has_oid(oid_slice) => Some(self.snmpInNoSuchNames.clone()), 
                oid_slice if self.snmpInBadValues.has_oid(oid_slice) => Some(self.snmpInBadValues.clone()), 
                oid_slice if self.snmpInReadOnlys.has_oid(oid_slice) => Some(self.snmpInReadOnlys.clone()), 
                oid_slice if self.snmpInGenErrs.has_oid(oid_slice) => Some(self.snmpInGenErrs.clone()), 
                oid_slice if self.snmpInTotalReqVars.has_oid(oid_slice) => Some(self.snmpInTotalReqVars.clone()), 
                oid_slice if self.snmpInTotalSetVars.has_oid(oid_slice) => Some(self.snmpInTotalSetVars.clone()), 
                oid_slice if self.snmpInGetRequests.has_oid(oid_slice) => Some(self.snmpInGetRequests.clone()), 
                oid_slice if self.snmpInGetNexts.has_oid(oid_slice) => Some(self.snmpInGetNexts.clone()), 
                oid_slice if self.snmpInSetRequests.has_oid(oid_slice) => Some(self.snmpInSetRequests.clone()), 
                oid_slice if self.snmpInGetResponses.has_oid(oid_slice) => Some(self.snmpInGetResponses.clone()), 
                oid_slice if self.snmpInTraps.has_oid(oid_slice) => Some(self.snmpInTraps.clone()),
                oid_slice if self.snmpOutTooBigs.has_oid(oid_slice) => Some(self.snmpOutTooBigs.clone()), 
                oid_slice if self.snmpOutNoSuchNames.has_oid(oid_slice) => Some(self.snmpOutNoSuchNames.clone()), 
                oid_slice if self.snmpOutBadValues.has_oid(oid_slice) => Some(self.snmpOutBadValues.clone()), 
                oid_slice if self.snmpOutGenErrs.has_oid(oid_slice) => Some(self.snmpOutGenErrs.clone()), 
                oid_slice if self.snmpOutGetRequests.has_oid(oid_slice) => Some(self.snmpOutGetRequests.clone()), 
                oid_slice if self.snmpOutGetNexts.has_oid(oid_slice) => Some(self.snmpOutGetNexts.clone()), 
                oid_slice if self.snmpOutSetRequests.has_oid(oid_slice) => Some(self.snmpOutSetRequests.clone()), 
                oid_slice if self.snmpOutGetResponses.has_oid(oid_slice) => Some(self.snmpOutGetResponses.clone()), 
                oid_slice if self.snmpOutTraps.has_oid(oid_slice) => Some(self.snmpOutTraps.clone()),
                oid_slice if self.snmpEnableAuthenTraps.has_oid(oid_slice) => Some(self.snmpEnableAuthenTraps.clone()), 
                _ => None,
            }
        }

        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.snmpInPkts.walk(client).await;
            self.snmpOutPkts.walk(client).await;
            self.snmpInBadVersions.walk(client).await;
            self.snmpInBadCommunityNames.walk(client).await;
            self.snmpInBadCommunityUses.walk(client).await;
            self.snmpInASNParseErrs.walk(client).await;
            self.snmpInTooBigs.walk(client).await;
            self.snmpInNoSuchNames.walk(client).await;
            self.snmpInBadValues.walk(client).await;
            self.snmpInReadOnlys.walk(client).await;
            self.snmpInGenErrs.walk(client).await;
            self.snmpInTotalReqVars.walk(client).await;
            self.snmpInTotalSetVars.walk(client).await;
            self.snmpInGetRequests.walk(client).await;
            self.snmpInGetNexts.walk(client).await;
            self.snmpInSetRequests.walk(client).await;
            self.snmpInGetResponses.walk(client).await;
            self.snmpInTraps.walk(client).await;
            self.snmpOutTooBigs.walk(client).await;
            self.snmpOutNoSuchNames.walk(client).await;
            self.snmpOutBadValues.walk(client).await;
            self.snmpOutGenErrs.walk(client).await;
            self.snmpOutGetRequests.walk(client).await;
            self.snmpOutGetNexts.walk(client).await;
            self.snmpOutSetRequests.walk(client).await;
            self.snmpOutGetResponses.walk(client).await;
            self.snmpOutTraps.walk(client).await;
            self.snmpEnableAuthenTraps.walk(client).await;
        }

        pub fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            ui.collapsing("Snmp", |ui| {
                self.snmpInPkts.egui_show(app, ctx, ui);
                self.snmpOutPkts.egui_show(app, ctx, ui);
                self.snmpInBadVersions.egui_show(app, ctx, ui);
                self.snmpInBadCommunityNames.egui_show(app, ctx, ui);
                self.snmpInBadCommunityUses.egui_show(app, ctx, ui);
                self.snmpInASNParseErrs.egui_show(app, ctx, ui);
                self.snmpInTooBigs.egui_show(app, ctx, ui);
                self.snmpInNoSuchNames.egui_show(app, ctx, ui);
                self.snmpInBadValues.egui_show(app, ctx, ui);
                self.snmpInReadOnlys.egui_show(app, ctx, ui);
                self.snmpInGenErrs.egui_show(app, ctx, ui);
                self.snmpInTotalReqVars.egui_show(app, ctx, ui);
                self.snmpInTotalSetVars.egui_show(app, ctx, ui);
                self.snmpInGetRequests.egui_show(app, ctx, ui);
                self.snmpInGetNexts.egui_show(app, ctx, ui);
                self.snmpInSetRequests.egui_show(app, ctx, ui);
                self.snmpInGetResponses.egui_show(app, ctx, ui);
                self.snmpInTraps.egui_show(app, ctx, ui);
                self.snmpOutTooBigs.egui_show(app, ctx, ui);
                self.snmpOutNoSuchNames.egui_show(app, ctx, ui);
                self.snmpOutBadValues.egui_show(app, ctx, ui);
                self.snmpOutGenErrs.egui_show(app, ctx, ui);
                self.snmpOutGetRequests.egui_show(app, ctx, ui);
                self.snmpOutGetNexts.egui_show(app, ctx, ui);
                self.snmpOutSetRequests.egui_show(app, ctx, ui);
                self.snmpOutGetResponses.egui_show(app, ctx, ui);
                self.snmpOutTraps.egui_show(app, ctx, ui);
                self.snmpEnableAuthenTraps.egui_show(app, ctx, ui);
            });
        }
    }

    impl Clone for MibObject {
        fn clone(&self) -> Self {
            MibObject {
                oid: self.oid.to_owned(),
                timestamp: self.timestamp.clone(),
                system: self.system.clone(),
                interfaces: self.interfaces.clone(),
                at: self.at.clone(),
                ip: self.ip.clone(),
                icmp: self.icmp.clone(),
                tcp: self.tcp.clone(),
                udp: self.udp.clone(),
                egp: self.egp.clone(),
                transmission: self.transmission.clone(),
                snmp: self.snmp.clone(),
            }
        }
    }

    impl Clone for System {
        fn clone(&self) -> Self {
            System {
                oid: self.oid.to_owned(),
                sysDesc: self.sysDesc.clone(),
                sysObjectID: self.sysObjectID.clone(),
                sysUpTime: self.sysUpTime.clone(),
                sysContact: self.sysContact.clone(),
                sysName: self.sysName.clone(),
                sysLocation: self.sysLocation.clone(),
                sysServices: self.sysServices.clone(),
            }
        }
    }

    impl Clone for Interfaces {
        fn clone(&self) -> Self {
            Interfaces {
                oid: self.oid.to_owned(),
                ifNumber: self.ifNumber.clone(),
                ifTable: self.ifTable.clone(),
            }
        }
    }

    impl Clone for IfTable {
        fn clone(&self) -> Self {
            IfTable {
                oid: self.oid.to_owned(),
                ifIndex: self.ifIndex.clone(),
                ifDescr: self.ifDescr.clone(),
                ifType: self.ifType.clone(),
                ifMtu: self.ifMtu.clone(),
                ifSpeed: self.ifSpeed.clone(),
                ifPhysAddress: self.ifPhysAddress.clone(),
                ifAdminStatus: self.ifAdminStatus.clone(),
                ifOperStatus: self.ifOperStatus.clone(),
                ifLastChange: self.ifLastChange.clone(),
                ifInOctets: self.ifInOctets.clone(),
                ifInUcastPkts: self.ifInUcastPkts.clone(),
                ifInNUcastPkts: self.ifInNUcastPkts.clone(),
                ifInDiscards: self.ifInDiscards.clone(),
                ifInErrors: self.ifInErrors.clone(),
                ifInUnknownProtos: self.ifInUnknownProtos.clone(),
                ifOutOctets: self.ifOutOctets.clone(),
                ifOutUcastPkts: self.ifOutUcastPkts.clone(),
                ifOutNUcastPkts: self.ifOutNUcastPkts.clone(),
                ifOutDiscards: self.ifOutDiscards.clone(),
                ifOutErrors: self.ifOutErrors.clone(),
                ifOutQLen: self.ifOutQLen.clone(),
                ifSpecific: self.ifSpecific.clone(),
            }
        }
    }

    impl Clone for At {
        fn clone(&self) -> Self {
            At {
                oid: self.oid.to_owned(),
                atTable: self.atTable.clone(),
            }
        }
    }

    impl Clone for AtTable {
        fn clone(&self) -> Self {
            AtTable {
                oid: self.oid.to_owned(),
                atIfIndex: self.atIfIndex.clone(),
                atPhysAddress: self.atPhysAddress.clone(),
                atNetAddress: self.atNetAddress.clone(),
            }
        }
    }

    impl Clone for Ip {
        fn clone(&self) -> Self {
            Ip {
                oid: self.oid.to_owned(),
                ipForwarding: self.ipForwarding.clone(),
                ipDefaultTTL: self.ipDefaultTTL.clone(),
                ipInReceives: self.ipInReceives.clone(),
                ipInHdrErrors: self.ipInHdrErrors.clone(),
                ipInAddrErrors: self.ipInAddrErrors.clone(),
                ipForwDatagrams: self.ipForwDatagrams.clone(),
                ipInUnknownProtos: self.ipInUnknownProtos.clone(),
                ipInDiscards: self.ipInDiscards.clone(),
                ipInDelivers: self.ipInDelivers.clone(),
                ipOutRequests: self.ipOutRequests.clone(),
                ipOutDiscards: self.ipOutDiscards.clone(),
                ipOutNoRoutes: self.ipOutNoRoutes.clone(),
                ipReasmTimeout: self.ipReasmTimeout.clone(),
                ipReasmReqds: self.ipReasmReqds.clone(),
                ipReasmOKs: self.ipReasmOKs.clone(),
                ipReasmFails: self.ipReasmFails.clone(),
                ipFragOKs: self.ipFragOKs.clone(),
                ipFragFails: self.ipFragFails.clone(),
                ipFragCreates: self.ipFragCreates.clone(),
                ipAddrTable: self.ipAddrTable.clone(),
                ipRouteTable: self.ipRouteTable.clone(),
                ipNetToMediaTable: self.ipNetToMediaTable.clone(),
                ipRoutingDiscards: self.ipRoutingDiscards.clone(),
            }
        }
    }

    impl Clone for IpAddrTable {
        fn clone(&self) -> Self {
            IpAddrTable {
                oid: self.oid.to_owned(),
                ipAdEntAddr: self.ipAdEntAddr.clone(),
                ipAdEntIfIndex: self.ipAdEntIfIndex.clone(),
                ipAdEntNetMask: self.ipAdEntNetMask.clone(),
                ipAdEntBcastAddr: self.ipAdEntBcastAddr.clone(),
                ipAdEntReasmMaxSize: self.ipAdEntReasmMaxSize.clone(),
            }
        }
    }

    impl Clone for IpRouteTable {
        fn clone(&self) -> Self {
            IpRouteTable {
                oid: self.oid.to_owned(),
                ipRouteDest: self.ipRouteDest.clone(),
                ipRouteIfIndex: self.ipRouteIfIndex.clone(),
                ipRouteMetric1: self.ipRouteMetric1.clone(),
                ipRouteMetric2: self.ipRouteMetric2.clone(),
                ipRouteMetric3: self.ipRouteMetric3.clone(),
                ipRouteMetric4: self.ipRouteMetric4.clone(),
                ipRouteNextHop: self.ipRouteNextHop.clone(),
                ipRouteType: self.ipRouteType.clone(),
                ipRouteProto: self.ipRouteProto.clone(),
                ipRouteAge: self.ipRouteAge.clone(),
                ipRouteMask: self.ipRouteMask.clone(),
                ipRouteMetric5: self.ipRouteMetric5.clone(),
                ipRouteInfo: self.ipRouteInfo.clone(),
            }
        }
    }

    impl Clone for IpNetToMediaTable {
        fn clone(&self) -> Self {
            IpNetToMediaTable {
                oid: self.oid.to_owned(),
                ipNetToMediaIfIndex: self.ipNetToMediaIfIndex.clone(),
                ipNetToMediaPhysAddress: self.ipNetToMediaPhysAddress.clone(),
                ipNetToMediaNetAddress: self.ipNetToMediaNetAddress.clone(),
                ipNetToMediaType: self.ipNetToMediaType.clone(),
            }
        }
    }

    impl Clone for Icmp {
        fn clone(&self) -> Self {
            Icmp {
                oid: self.oid.to_owned(),
                icmpInMsgs: self.icmpInMsgs.clone(),
                icmpInErrors: self.icmpInErrors.clone(),
                icmpInDestUnreachs: self.icmpInDestUnreachs.clone(),
                icmpInTimeExcds: self.icmpInTimeExcds.clone(),
                icmpInParmProbs: self.icmpInParmProbs.clone(),
                icmpInSrcQuenchs: self.icmpInSrcQuenchs.clone(),
                icmpInRedirects: self.icmpInRedirects.clone(),
                icmpInEchos: self.icmpInEchos.clone(),
                icmpInEchoReps: self.icmpInEchoReps.clone(),
                icmpInTimestamps: self.icmpInTimestamps.clone(),
                icmpInTimestampReps: self.icmpInTimestampReps.clone(),
                icmpInAddrMasks: self.icmpInAddrMasks.clone(),
                icmpInAddrMaskReps: self.icmpInAddrMaskReps.clone(),
                icmpOutMsgs: self.icmpOutMsgs.clone(),
                icmpOutErrors: self.icmpOutErrors.clone(),
                icmpOutDestUnreachs: self.icmpOutDestUnreachs.clone(),
                icmpOutTimeExcds: self.icmpOutTimeExcds.clone(),
                icmpOutParmProbs: self.icmpOutParmProbs.clone(),
                icmpOutSrcQuenchs: self.icmpOutSrcQuenchs.clone(),
                icmpOutRedirects: self.icmpOutRedirects.clone(),
                icmpOutEchos: self.icmpOutEchos.clone(),
                icmpOutEchoReps: self.icmpOutEchoReps.clone(),
                icmpOutTimestamps: self.icmpOutTimestamps.clone(),
                icmpOutTimestampReps: self.icmpOutTimestampReps.clone(),
                icmpOutAddrMasks: self.icmpOutAddrMasks.clone(),
                icmpOutAddrMaskReps: self.icmpOutAddrMaskReps.clone(),
            }
        }
    }

    impl Clone for Tcp {
        fn clone(&self) -> Self {
            Tcp {
                oid: self.oid.to_owned(),
                tcpRtoAlgorithm: self.tcpRtoAlgorithm.clone(),
                tcpRtoMin: self.tcpRtoMin.clone(),
                tcpRtoMax: self.tcpRtoMax.clone(),
                tcpMaxConn: self.tcpMaxConn.clone(),
                tcpActiveOpens: self.tcpActiveOpens.clone(),
                tcpPassiveOpens: self.tcpPassiveOpens.clone(),
                tcpAttemptFails: self.tcpAttemptFails.clone(),
                tcpEstabResets: self.tcpEstabResets.clone(),
                tcpCurrEstab: self.tcpCurrEstab.clone(),
                tcpInSegs: self.tcpInSegs.clone(),
                tcpOutSegs: self.tcpOutSegs.clone(),
                tcpRetransSegs: self.tcpRetransSegs.clone(),
                tcpConnTable: self.tcpConnTable.clone(),
                tcpInErrs: self.tcpInErrs.clone(),
                tcpOutRsts: self.tcpOutRsts.clone(),
            }
        }
    }

    impl Clone for TcpConnTable {
        fn clone(&self) -> Self {
            TcpConnTable {
                oid: self.oid.to_owned(),
                tcpConnState: self.tcpConnState.clone(),
                tcpConnLocalAddress: self.tcpConnLocalAddress.clone(),
                tcpConnLocalPort: self.tcpConnLocalPort.clone(),
                tcpConnRemAddress: self.tcpConnRemAddress.clone(),
                tcpConnRemPort: self.tcpConnRemPort.clone(),
            }
        }
    }

    impl Clone for Udp {
        fn clone(&self) -> Self {
            Udp {
                oid: self.oid.to_owned(),
                udpInDatagrams: self.udpInDatagrams.clone(),
                udpNoPorts: self.udpNoPorts.clone(),
                udpInErrors: self.udpInErrors.clone(),
                udpOutDatagrams: self.udpOutDatagrams.clone(),
                udpTable: self.udpTable.clone(),
            }
        }
    }

    impl Clone for UdpTable {
        fn clone(&self) -> Self {
            UdpTable {
                oid: self.oid.to_owned(),
                udpLocalAddress: self.udpLocalAddress.clone(),
                udpLocalPort: self.udpLocalPort.clone(),
            }
        }
    }

    impl Clone for Egp {
        fn clone(&self) -> Self {
            Egp {
                oid: self.oid.to_owned(),
                egpInMsgs: self.egpInMsgs.clone(),
                egpInErrors: self.egpInErrors.clone(),
                egpOutMsgs: self.egpOutMsgs.clone(),
                egpOutErrors: self.egpOutErrors.clone(),
                egpNeighTable: self.egpNeighTable.clone(),
                egpAs: self.egpAs.clone(),
            }
        }
    }

    impl Clone for EgpNeighTable {
        fn clone(&self) -> Self {
            EgpNeighTable {
                oid: self.oid.to_owned(),
                egpNeighState: self.egpNeighState.clone(),
                egpNeighAddr: self.egpNeighAddr.clone(),
                egpNeighAs: self.egpNeighAs.clone(),
                egpNeighInMsgs: self.egpNeighInMsgs.clone(),
                egpNeighInErrs: self.egpNeighInErrs.clone(),
                egpNeighOutMsgs: self.egpNeighOutMsgs.clone(),
                egpNeighOutErrs: self.egpNeighOutErrs.clone(),
                egpNeighInErrMsgs: self.egpNeighInErrMsgs.clone(),
                egpNeighOutErrMsgs: self.egpNeighOutErrMsgs.clone(),
                egpNeighStateUps: self.egpNeighStateUps.clone(),
                egpNeighStateDowns: self.egpNeighStateDowns.clone(),
                egpNeighIntervalHello: self.egpNeighIntervalHello.clone(),
                egpNeighIntervalPoll: self.egpNeighIntervalPoll.clone(),
                egpNeighMode: self.egpNeighMode.clone(),
                egpNeighEventTrigger: self.egpNeighEventTrigger.clone(),
            }
        }
    }

    impl Clone for Snmp {
        fn clone(&self) -> Self {
            Snmp {
                oid: self.oid.to_owned(),
                snmpInPkts: self.snmpInPkts.clone(),
                snmpOutPkts: self.snmpOutPkts.clone(),
                snmpInBadVersions: self.snmpInBadVersions.clone(),
                snmpInBadCommunityNames: self.snmpInBadCommunityNames.clone(),
                snmpInBadCommunityUses: self.snmpInBadCommunityUses.clone(),
                snmpInASNParseErrs: self.snmpInASNParseErrs.clone(),
                snmpInTooBigs: self.snmpInTooBigs.clone(),
                snmpInNoSuchNames: self.snmpInNoSuchNames.clone(),
                snmpInBadValues: self.snmpInBadValues.clone(),
                snmpInReadOnlys: self.snmpInReadOnlys.clone(),
                snmpInGenErrs: self.snmpInGenErrs.clone(),
                snmpInTotalReqVars: self.snmpInTotalReqVars.clone(),
                snmpInTotalSetVars: self.snmpInTotalSetVars.clone(),
                snmpInGetRequests: self.snmpInGetRequests.clone(),
                snmpInGetNexts: self.snmpInGetNexts.clone(),
                snmpInSetRequests: self.snmpInSetRequests.clone(),
                snmpInGetResponses: self.snmpInGetResponses.clone(),
                snmpInTraps: self.snmpInTraps.clone(),
                snmpOutTooBigs: self.snmpOutTooBigs.clone(),
                snmpOutNoSuchNames: self.snmpOutNoSuchNames.clone(),
                snmpOutBadValues: self.snmpOutBadValues.clone(),
                snmpOutGenErrs: self.snmpOutGenErrs.clone(),
                snmpOutGetRequests: self.snmpOutGetRequests.clone(),
                snmpOutGetNexts: self.snmpOutGetNexts.clone(),
                snmpOutSetRequests: self.snmpOutSetRequests.clone(),
                snmpOutGetResponses: self.snmpOutGetResponses.clone(),
                snmpOutTraps: self.snmpOutTraps.clone(),
                snmpEnableAuthenTraps: self.snmpEnableAuthenTraps.clone(),
            }
        }
    }

    impl MibObject {
        pub fn new() -> Self {
            MibObject {
                oid: vec![1, 3, 6, 1, 2, 1],
                timestamp: chrono::Local::now().timestamp(),
                system: System {
                    oid: vec![1, 3, 6, 1, 2, 1, 1],
                    sysDesc: MibValue::string(mvstring {name: "sysDesc".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 1, 1],mutable: false,value: vec![]}), // DisplayString
                    sysObjectID: MibValue::oid(mvoid {name: "sysObjectID".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 1, 2],mutable: false,value: vec![]}), // OBJECT_IDENTIFIER
                    sysUpTime: MibValue::intu32(mvintu32 {name: "sysUpTime".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 1, 3],mutable: false,value: vec![]}), // TimeTicks
                    sysContact: MibValue::string(mvstring {name: "sysContact".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 1, 4],mutable: true,value: vec![]}), // DisplayString
                    sysName: MibValue::string(mvstring {name: "sysName".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 1, 5],mutable: true,value: vec![]}), // DisplayString
                    sysLocation: MibValue::string(mvstring {name: "sysLocation".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 1, 6],mutable: true,value: vec![]}), // DisplayString
                    sysServices: MibValue::inti32(mvinti32 {name: "sysServices".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 1, 7],mutable: false,value: vec![]}), // INTEGER
                },
                interfaces: Interfaces {
                    oid: vec![1, 3, 6, 1, 2, 1, 2],
                    ifNumber: MibValue::inti32(mvinti32 {name: "ifNumber".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 1],mutable: false,value: vec![]}), // INTEGER
                    ifTable: IfTable {
                        oid: vec![1, 3, 6, 1, 2, 1, 2, 2],
                        ifIndex: MibValue::inti32(mvinti32 {name: "ifIndex".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 1],mutable: false,value: vec![]}), // INTEGER
                        ifDescr: MibValue::string(mvstring {name: "ifDescr".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 2],mutable: false,value: vec![]}), // DisplayString
                        ifType: MibValue::inti32(mvinti32 {name: "ifType".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 3],mutable: false,value: vec![]}), // INTEGER
                        ifMtu: MibValue::inti32(mvinti32 {name: "ifMtu".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 4],mutable: false,value: vec![]}), // INTEGER
                        ifSpeed: MibValue::intu32(mvintu32 {name: "ifSpeed".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 5],mutable: false,value: vec![]}), // Gauge
                        ifPhysAddress: MibValue::ipv6(mvipv6 {name: "ifPhysAddress".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 6],mutable: false,value: vec![]}), // PhysAddress
                        ifAdminStatus: MibValue::inti32(mvinti32 {name: "ifAdminStatus".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 7],mutable: true,value: vec![]}), // INTEGER
                        ifOperStatus: MibValue::inti32(mvinti32 {name: "ifOperStatus".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 8],mutable: false,value: vec![]}), // INTEGER
                        ifLastChange: MibValue::intu32(mvintu32 {name: "ifLastChange".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 9],mutable: false,value: vec![]}), // TimeTicks
                        ifInOctets: MibValue::intu32(mvintu32 {name: "ifInOctets".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 10],mutable: false,value: vec![]}), // Counter
                        ifInUcastPkts: MibValue::intu32(mvintu32 {name: "ifInUcastPkts".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 11],mutable: false,value: vec![]}), // Counter
                        ifInNUcastPkts: MibValue::intu32(mvintu32 {name: "ifInNUcastPkts".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 12],mutable: false,value: vec![]}), // Counter
                        ifInDiscards: MibValue::intu32(mvintu32 {name: "ifInDiscards".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 13],mutable: false,value: vec![]}), // Counter
                        ifInErrors: MibValue::intu32(mvintu32 {name: "ifInErrors".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 14],mutable: false,value: vec![]}), // Counter
                        ifInUnknownProtos: MibValue::intu32(mvintu32 {name: "ifInUnknownProtos".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 15],mutable: false,value: vec![]}), // Counter
                        ifOutOctets: MibValue::intu32(mvintu32 {name: "ifOutOctets".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 16],mutable: false,value: vec![]}), // Counter
                        ifOutUcastPkts: MibValue::intu32(mvintu32 {name: "ifOutUcastPkts".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 17],mutable: false,value: vec![]}), // Counter
                        ifOutNUcastPkts: MibValue::intu32(mvintu32 {name: "ifOutNUcastPkts".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 18],mutable: false,value: vec![]}), // Counter
                        ifOutDiscards: MibValue::intu32(mvintu32 {name: "ifOutDiscards".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 19],mutable: false,value: vec![]}), // Counter
                        ifOutErrors: MibValue::intu32(mvintu32 {name: "ifOutErrors".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 20],mutable: false,value: vec![]}), // Counter
                        ifOutQLen: MibValue::intu32(mvintu32 {name: "ifOutQLen".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 21],mutable: false,value: vec![]}), // Gauge
                        ifSpecific: MibValue::oid(mvoid {name: "ifSpecific".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 2, 2, 1, 22],mutable: false,value: vec![]}), // OBJECT_IDENTIFIER
                    },
                },
                at: At {
                    oid: vec![1, 3, 6, 1, 2, 1, 3],
                    atTable: AtTable {
                        oid: vec![1, 3, 6, 1, 2, 1, 3, 1],
                        atIfIndex: MibValue::inti32(mvinti32 {name: "atIfIndex".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 3, 1, 1, 1],mutable: true,value: vec![]}), // INTEGER
                        atPhysAddress: MibValue::ipv6(mvipv6 {name: "atPhysAddress".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 3, 1, 1, 2],mutable: true,value: vec![]}), // PhysAddress
                        atNetAddress: MibValue::ipv4(mvipv4 {name: "atNetAddress".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 3, 1, 1, 3],mutable: true,value: vec![]}), // IpAddress
                    },
                },
                ip: Ip {
                    oid: vec![1, 3, 6, 1, 2, 1, 4],
                    ipForwarding: MibValue::inti32(mvinti32 {name: "ipForwarding".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 1],mutable: true,value: vec![]}), // INTEGER
                    ipDefaultTTL: MibValue::inti32(mvinti32 {name: "ipDefaultTTL".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 2],mutable: true,value: vec![]}), // INTEGER
                    ipInReceives: MibValue::intu32(mvintu32 {name: "ipInReceives".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 3],mutable: false,value: vec![]}), // Counter
                    ipInHdrErrors: MibValue::intu32(mvintu32 {name: "ipInHdrErrors".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 4],mutable: false,value: vec![]}), // Counter
                    ipInAddrErrors: MibValue::intu32(mvintu32 {name: "ipInAddrErrors".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 5],mutable: false,value: vec![]}), // Counter
                    ipForwDatagrams: MibValue::intu32(mvintu32 {name: "ipForwDatagrams".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 6],mutable: false,value: vec![]}), // Counter
                    ipInUnknownProtos: MibValue::intu32(mvintu32 {name: "ipInUnknownProtos".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 7],mutable: false,value: vec![]}), // Counter
                    ipInDiscards: MibValue::intu32(mvintu32 {name: "ipInDiscards".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 8],mutable: false,value: vec![]}), // Counter
                    ipInDelivers: MibValue::intu32(mvintu32 {name: "ipInDelivers".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 9],mutable: false,value: vec![]}), // Counter
                    ipOutRequests: MibValue::intu32(mvintu32 {name: "ipOutRequests".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 10],mutable: false,value: vec![]}), // Counter
                    ipOutDiscards: MibValue::intu32(mvintu32 {name: "ipOutDiscards".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 11],mutable: false,value: vec![]}), // Counter
                    ipOutNoRoutes: MibValue::intu32(mvintu32 {name: "ipOutNoRoutes".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 12],mutable: false,value: vec![]}), // Counter
                    ipReasmTimeout: MibValue::inti32(mvinti32 {name: "ipReasmTimeout".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 13],mutable: false,value: vec![]}), // INTEGER
                    ipReasmReqds: MibValue::intu32(mvintu32 {name: "ipReasmReqds".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 14],mutable: false,value: vec![]}), // Counter
                    ipReasmOKs: MibValue::intu32(mvintu32 {name: "ipReasmOKs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 15],mutable: false,value: vec![]}), // Counter
                    ipReasmFails: MibValue::intu32(mvintu32 {name: "ipReasmFails".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 16],mutable: false,value: vec![]}), // Counter
                    ipFragOKs: MibValue::intu32(mvintu32 {name: "ipFragOKs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 17],mutable: false,value: vec![]}), // Counter
                    ipFragFails: MibValue::intu32(mvintu32 {name: "ipFragFails".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 18],mutable: false,value: vec![]}), // Counter
                    ipFragCreates: MibValue::intu32(mvintu32 {name: "ipFragCreates".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 19],mutable: false,value: vec![]}), // Counter
                    ipAddrTable: IpAddrTable {
                        oid: vec![1, 3, 6, 1, 2, 1, 4, 20],
                        ipAdEntAddr: MibValue::ipv4(mvipv4 {name: "ipAdEntAddr".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 20, 1, 1],mutable: false,value: vec![]}), // IpAddress
                        ipAdEntIfIndex: MibValue::inti32(mvinti32 {name: "ipAdEntIfIndex".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 20, 1, 2],mutable: false,value: vec![]}), // INTEGER
                        ipAdEntNetMask: MibValue::ipv4(mvipv4 {name: "ipAdEntNetMask".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 20, 1, 3],mutable: false,value: vec![]}), // IpAddress
                        ipAdEntBcastAddr: MibValue::inti32(mvinti32 {name: "ipAdEntBcastAddr".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 20, 1, 4],mutable: false,value: vec![]}), // INTEGER
                        ipAdEntReasmMaxSize: MibValue::inti32(mvinti32 {name: "ipAdEntReasmMaxSize".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 20, 1, 5],mutable: false,value: vec![]}), // INTEGER
                    },
                    ipRouteTable: IpRouteTable {
                        oid: vec![1, 3, 6, 1, 2, 1, 4, 21],
                        ipRouteDest: MibValue::ipv4(mvipv4 {name: "ipRouteDest".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 21, 1, 1],mutable: true,value: vec![]}), // IpAddress
                        ipRouteIfIndex: MibValue::inti32(mvinti32 {name: "ipRouteIfIndex".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 21, 1, 2],mutable: true,value: vec![]}), // INTEGER
                        ipRouteMetric1: MibValue::inti32(mvinti32 {name: "ipRouteMetric1".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 21, 1, 3],mutable: true,value: vec![]}), // INTEGER
                        ipRouteMetric2: MibValue::inti32(mvinti32 {name: "ipRouteMetric2".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 21, 1, 4],mutable: true,value: vec![]}), // INTEGER
                        ipRouteMetric3: MibValue::inti32(mvinti32 {name: "ipRouteMetric3".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 21, 1, 5],mutable: true,value: vec![]}), // INTEGER
                        ipRouteMetric4: MibValue::inti32(mvinti32 {name: "ipRouteMetric4".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 21, 1, 6],mutable: true,value: vec![]}), // INTEGER
                        ipRouteNextHop: MibValue::ipv4(mvipv4 {name: "ipRouteNextHop".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 21, 1, 7],mutable: true,value: vec![]}), // IpAddress
                        ipRouteType: MibValue::inti32(mvinti32 {name: "ipRouteType".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 21, 1, 8],mutable: true,value: vec![]}), // INTEGER
                        ipRouteProto: MibValue::inti32(mvinti32 {name: "ipRouteProto".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 21, 1, 9],mutable: true,value: vec![]}), // INTEGER
                        ipRouteAge: MibValue::inti32(mvinti32 {name: "ipRouteAge".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 21, 1, 10],mutable: true,value: vec![]}), // INTEGER
                        ipRouteMask: MibValue::ipv4(mvipv4 {name: "ipRouteMask".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 21, 1, 11],mutable: true,value: vec![]}), // IpAddress
                        ipRouteMetric5: MibValue::inti32(mvinti32 {name: "ipRouteMetric5".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 21, 1, 12],mutable: true,value: vec![]}), // INTEGER
                        ipRouteInfo: MibValue::oid(mvoid {name: "ipRouteInfo".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 21, 1, 13],mutable: true,value: vec![]}), // OBJECT_IDENTIFIER
                    },
                    ipNetToMediaTable: IpNetToMediaTable {
                        oid: vec![1, 3, 6, 1, 2, 1, 4, 22],
                        ipNetToMediaIfIndex: MibValue::inti32(mvinti32 {name: "ipNetToMediaIfIndex".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 22, 1, 1],mutable: true,value: vec![]}), // INTEGER
                        ipNetToMediaPhysAddress: MibValue::ipv6(mvipv6 {name: "ipNetToMediaPhysAddress".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 22, 1, 2],mutable: true,value: vec![]}), // PhysAddress
                        ipNetToMediaNetAddress: MibValue::ipv4(mvipv4 {name: "ipNetToMediaNetAddress".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 22, 1, 3],mutable: true,value: vec![]}), // IpAddress
                        ipNetToMediaType: MibValue::inti32(mvinti32 {name: "ipNetToMediaType".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 22, 1, 4],mutable: true,value: vec![]}), // INTEGER
                    },
                    ipRoutingDiscards: MibValue::intu32(mvintu32 {name: "ipRoutingDiscards".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 4, 23],mutable: false,value: vec![]}), // Counter
                },
                icmp: Icmp {
                    oid: vec![1, 3, 6, 1, 2, 1, 5],
                    icmpInMsgs: MibValue::intu32(mvintu32 {name: "icmpInMsgs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 1],mutable: false,value: vec![]}), // Counter
                    icmpInErrors: MibValue::intu32(mvintu32 {name: "icmpInErrors".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 2],mutable: false,value: vec![]}), // Counter
                    icmpInDestUnreachs: MibValue::intu32(mvintu32 {name: "icmpInDestUnreachs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 3],mutable: false,value: vec![]}), // Counter
                    icmpInTimeExcds: MibValue::intu32(mvintu32 {name: "icmpInTimeExcds".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 4],mutable: false,value: vec![]}), // Counter
                    icmpInParmProbs: MibValue::intu32(mvintu32 {name: "icmpInParmProbs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 5],mutable: false,value: vec![]}), // Counter
                    icmpInSrcQuenchs: MibValue::intu32(mvintu32 {name: "icmpInSrcQuenchs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 6],mutable: false,value: vec![]}), // Counter
                    icmpInRedirects: MibValue::intu32(mvintu32 {name: "icmpInRedirects".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 7],mutable: false,value: vec![]}), // Counter
                    icmpInEchos: MibValue::intu32(mvintu32 {name: "icmpInEchos".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 8],mutable: false,value: vec![]}), // Counter
                    icmpInEchoReps: MibValue::intu32(mvintu32 {name: "icmpInEchoReps".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 9],mutable: false,value: vec![]}), // Counter
                    icmpInTimestamps: MibValue::intu32(mvintu32 {name: "icmpInTimestamps".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 10],mutable: false,value: vec![]}), // Counter
                    icmpInTimestampReps: MibValue::intu32(mvintu32 {name: "icmpInTimestampReps".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 11],mutable: false,value: vec![]}), // counter
                    icmpInAddrMasks: MibValue::intu32(mvintu32 {name: "icmpInAddrMasks".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 12],mutable: false,value: vec![]}), // Counter
                    icmpInAddrMaskReps: MibValue::intu32(mvintu32 {name: "icmpInAddrMaskReps".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 13],mutable: false,value: vec![]}), // counter
                    icmpOutMsgs: MibValue::intu32(mvintu32 {name: "icmpOutMsgs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 14],mutable: false,value: vec![]}), // Counter
                    icmpOutErrors: MibValue::intu32(mvintu32 {name: "icmpOutErrors".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 15],mutable: false,value: vec![]}), // Counter
                    icmpOutDestUnreachs: MibValue::intu32(mvintu32 {name: "icmpOutDestUnreachs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 16],mutable: false,value: vec![]}), // counter
                    icmpOutTimeExcds: MibValue::intu32(mvintu32 {name: "icmpOutTimeExcds".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 17],mutable: false,value: vec![]}), // Counter
                    icmpOutParmProbs: MibValue::intu32(mvintu32 {name: "icmpOutParmProbs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 18],mutable: false,value: vec![]}), // Counter
                    icmpOutSrcQuenchs: MibValue::intu32(mvintu32 {name: "icmpOutSrcQuenchs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 19],mutable: false,value: vec![]}), // Counter
                    icmpOutRedirects: MibValue::intu32(mvintu32 {name: "icmpOutRedirects".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 20],mutable: false,value: vec![]}), // Counter
                    icmpOutEchos: MibValue::intu32(mvintu32 {name: "icmpOutEchos".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 21],mutable: false,value: vec![]}), // Counter
                    icmpOutEchoReps: MibValue::intu32(mvintu32 {name: "icmpOutEchoReps".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 22],mutable: false,value: vec![]}), // Counter
                    icmpOutTimestamps: MibValue::intu32(mvintu32 {name: "icmpOutTimestamps".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 23],mutable: false,value: vec![]}), // Counter
                    icmpOutTimestampReps: MibValue::intu32(mvintu32 {name: "icmpOutTimestampReps".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 24],mutable: false,value: vec![]}), // counter
                    icmpOutAddrMasks: MibValue::intu32(mvintu32 {name: "icmpOutAddrMasks".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 25],mutable: false,value: vec![]}), // Counter
                    icmpOutAddrMaskReps: MibValue::intu32(mvintu32 {name: "icmpOutAddrMaskReps".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 5, 26],mutable: false,value: vec![]}), // counter
                },
                tcp: Tcp {
                    oid: vec![1, 3, 6, 1, 2, 1, 6],
                    tcpRtoAlgorithm: MibValue::inti32(mvinti32 {name: "tcpRtoAlgorithm".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 1],mutable: false,value: vec![]}), // INTEGER
                    tcpRtoMin: MibValue::inti32(mvinti32 {name: "tcpRtoMin".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 2],mutable: false,value: vec![]}), // INTEGER
                    tcpRtoMax: MibValue::inti32(mvinti32 {name: "tcpRtoMax".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 3],mutable: false,value: vec![]}), // INTEGER
                    tcpMaxConn: MibValue::inti32(mvinti32 {name: "tcpMaxConn".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 4],mutable: false,value: vec![]}), // INTEGER
                    tcpActiveOpens: MibValue::intu32(mvintu32 {name: "tcpActiveOpens".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 5],mutable: false,value: vec![]}), // Counter
                    tcpPassiveOpens: MibValue::intu32(mvintu32 {name: "tcpPassiveOpens".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 6],mutable: false,value: vec![]}), // Counter
                    tcpAttemptFails: MibValue::intu32(mvintu32 {name: "tcpAttemptFails".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 7],mutable: false,value: vec![]}), // Counter
                    tcpEstabResets: MibValue::intu32(mvintu32 {name: "tcpEstabResets".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 8],mutable: false,value: vec![]}), // Counter
                    tcpCurrEstab: MibValue::intu32(mvintu32 {name: "tcpCurrEstab".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 9],mutable: false,value: vec![]}), // Gauge
                    tcpInSegs: MibValue::intu32(mvintu32 {name: "tcpInSegs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 10],mutable: false,value: vec![]}), // Counter
                    tcpOutSegs: MibValue::intu32(mvintu32 {name: "tcpOutSegs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 11],mutable: false,value: vec![]}), // Counter
                    tcpRetransSegs: MibValue::intu32(mvintu32 {name: "tcpRetransSegs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 12],mutable: false,value: vec![]}), // Counter
                    tcpConnTable: TcpConnTable {
                        oid: vec![1, 3, 6, 1, 2, 1, 6, 13],
                        tcpConnState: MibValue::inti32(mvinti32 {name: "tcpConnState".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 13, 1, 1],mutable: true,value: vec![]}), // INTEGER
                        tcpConnLocalAddress: MibValue::ipv4(mvipv4 {name: "tcpConnLocalAddress".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 13, 1, 2],mutable: false,value: vec![]}), // IpAddress
                        tcpConnLocalPort: MibValue::inti32(mvinti32 {name: "tcpConnLocalPort".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 13, 1, 3],mutable: false,value: vec![]}), // INTEGER
                        tcpConnRemAddress: MibValue::ipv4(mvipv4 {name: "tcpConnRemAddress".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 13, 1, 4],mutable: false,value: vec![]}), // IpAddress
                        tcpConnRemPort: MibValue::inti32(mvinti32 {name: "tcpConnRemPort".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 13, 1, 5],mutable: false,value: vec![]}), // INTEGER
                    },
                    tcpInErrs: MibValue::intu32(mvintu32 {name: "tcpInErrs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 14],mutable: false,value: vec![]}), // Counter
                    tcpOutRsts: MibValue::intu32(mvintu32 {name: "tcpOutRsts".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 6, 15],mutable: false,value: vec![]}), // Counter
                },
                udp: Udp {
                    oid: vec![1, 3, 6, 1, 2, 1, 7],
                    udpInDatagrams: MibValue::intu32(mvintu32 {name: "udpInDatagrams".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 7, 1],mutable: false,value: vec![]}), // Counter
                    udpNoPorts: MibValue::intu32(mvintu32 {name: "udpNoPorts".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 7, 2],mutable: false,value: vec![]}), // Counter
                    udpInErrors: MibValue::intu32(mvintu32 {name: "udpInErrors".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 7, 3],mutable: false,value: vec![]}), // Counter
                    udpOutDatagrams: MibValue::intu32(mvintu32 {name: "udpOutDatagrams".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 7, 4],mutable: false,value: vec![]}), // Counter
                    udpTable: UdpTable {
                        oid: vec![1, 3, 6, 1, 2, 1, 7, 5],
                        udpLocalAddress: MibValue::ipv4(mvipv4 {name: "udpLocalAddress".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 7, 5, 1, 1],mutable: false,value: vec![]}), // IpAddress
                        udpLocalPort: MibValue::inti32(mvinti32 {name: "udpLocalPort".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 7, 5, 1, 2],mutable: false,value: vec![]}), // INTEGER
                    },
                },
                egp: Egp {
                    oid: vec![1, 3, 6, 1, 2, 1, 8],
                    egpInMsgs: MibValue::intu32(mvintu32 {name: "egpInMsgs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 1],mutable: false,value: vec![]}), // Counter
                    egpInErrors: MibValue::intu32(mvintu32 {name: "egpInErrors".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 2],mutable: false,value: vec![]}), // Counter
                    egpOutMsgs: MibValue::intu32(mvintu32 {name: "egpOutMsgs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 3],mutable: false,value: vec![]}), // Counter
                    egpOutErrors: MibValue::intu32(mvintu32 {name: "egpOutErrors".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 4],mutable: false,value: vec![]}), // Counter
                    egpNeighTable: EgpNeighTable {
                        oid: vec![1, 3, 6, 1, 2, 1, 8, 5],
                        egpNeighState: MibValue::inti32(mvinti32 {name: "egpNeighState".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 1],mutable: false,value: vec![]}), // INTEGER
                        egpNeighAddr: MibValue::ipv4(mvipv4 {name: "egpNeighAddr".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 2],mutable: false,value: vec![]}), // IpAddress
                        egpNeighAs: MibValue::inti32(mvinti32 {name: "egpNeighAs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 3],mutable: false,value: vec![]}), // INTEGER
                        egpNeighInMsgs: MibValue::intu32(mvintu32 {name: "egpNeighInMsgs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 4],mutable: false,value: vec![]}), // Counter
                        egpNeighInErrs: MibValue::intu32(mvintu32 {name: "egpNeighInErrs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 5],mutable: false,value: vec![]}), // Counter
                        egpNeighOutMsgs: MibValue::intu32(mvintu32 {name: "egpNeighOutMsgs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 6],mutable: false,value: vec![]}), // Counter
                        egpNeighOutErrs: MibValue::intu32(mvintu32 {name: "egpNeighOutErrs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 7],mutable: false,value: vec![]}), // Counter
                        egpNeighInErrMsgs: MibValue::intu32(mvintu32 {name: "egpNeighInErrMsgs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 8],mutable: false,value: vec![]}), // Counter
                        egpNeighOutErrMsgs: MibValue::intu32(mvintu32 {name: "egpNeighOutErrMsgs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 9],mutable: false,value: vec![]}), // Counter
                        egpNeighStateUps: MibValue::intu32(mvintu32 {name: "egpNeighStateUps".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 10],mutable: false,value: vec![]}), // Counter
                        egpNeighStateDowns: MibValue::intu32(mvintu32 {name: "egpNeighStateDowns".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 11],mutable: false,value: vec![]}), // Counter
                        egpNeighIntervalHello: MibValue::inti32(mvinti32 {name: "egpNeighIntervalHello".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 12],mutable: false,value: vec![]}), // INTEGER
                        egpNeighIntervalPoll: MibValue::inti32(mvinti32 {name: "egpNeighIntervalPoll".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 13],mutable: false,value: vec![]}), // INTEGER
                        egpNeighMode: MibValue::inti32(mvinti32 {name: "egpNeighMode".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 14],mutable: false,value: vec![]}), // INTEGER
                        egpNeighEventTrigger: MibValue::inti32(mvinti32 {name: "egpNeighEventTrigger".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 5, 1, 15],mutable: true,value: vec![]}), // INTEGER
                    },
                    egpAs: MibValue::inti32(mvinti32 {name: "egpAs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 8, 6],mutable: false,value: vec![]}), // INTEGER
                },
                transmission: MibValue::oid(mvoid {name: "transmission".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 10],mutable: false,value: vec![]}), // objectidentity
                snmp: Snmp {
                    oid: vec![1, 3, 6, 1, 2, 1, 11],
                    snmpInPkts: MibValue::intu32(mvintu32 {name: "snmpInPkts".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 1],mutable: false,value: vec![]}), // Counter
                    snmpOutPkts: MibValue::intu32(mvintu32 {name: "snmpOutPkts".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 2],mutable: false,value: vec![]}), // Counter
                    snmpInBadVersions: MibValue::intu32(mvintu32 {name: "snmpInBadVersions".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 3],mutable: false,value: vec![]}), // Counter
                    snmpInBadCommunityNames: MibValue::intu32(mvintu32 {name: "snmpInBadCommunityNames".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 4],mutable: false,value: vec![]}), // Counter
                    snmpInBadCommunityUses: MibValue::intu32(mvintu32 {name: "snmpInBadCommunityUses".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 5],mutable: false,value: vec![]}), // Counter
                    snmpInASNParseErrs: MibValue::intu32(mvintu32 {name: "snmpInASNParseErrs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 6],mutable: false,value: vec![]}), // Counter
                    snmpInTooBigs: MibValue::intu32(mvintu32 {name: "snmpInTooBigs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 8],mutable: false,value: vec![]}), // Counter
                    snmpInNoSuchNames: MibValue::intu32(mvintu32 {name: "snmpInNoSuchNames".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 9],mutable: false,value: vec![]}), // Counter
                    snmpInBadValues: MibValue::intu32(mvintu32 {name: "snmpInBadValues".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 10],mutable: false,value: vec![]}), // Counter
                    snmpInReadOnlys: MibValue::intu32(mvintu32 {name: "snmpInReadOnlys".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 11],mutable: false,value: vec![]}), // Counter
                    snmpInGenErrs: MibValue::intu32(mvintu32 {name: "snmpInGenErrs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 12],mutable: false,value: vec![]}), // Counter
                    snmpInTotalReqVars: MibValue::intu32(mvintu32 {name: "snmpInTotalReqVars".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 13],mutable: false,value: vec![]}), // Counter
                    snmpInTotalSetVars: MibValue::intu32(mvintu32 {name: "snmpInTotalSetVars".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 14],mutable: false,value: vec![]}), // Counter
                    snmpInGetRequests: MibValue::intu32(mvintu32 {name: "snmpInGetRequests".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 15],mutable: false,value: vec![]}), // Counter
                    snmpInGetNexts: MibValue::intu32(mvintu32 {name: "snmpInGetNexts".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 16],mutable: false,value: vec![]}), // Counter
                    snmpInSetRequests: MibValue::intu32(mvintu32 {name: "snmpInSetRequests".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 17],mutable: false,value: vec![]}), // Counter
                    snmpInGetResponses: MibValue::intu32(mvintu32 {name: "snmpInGetResponses".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 18],mutable: false,value: vec![]}), // Counter
                    snmpInTraps: MibValue::intu32(mvintu32 {name: "snmpInTraps".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 19],mutable: false,value: vec![]}), // Counter
                    snmpOutTooBigs: MibValue::intu32(mvintu32 {name: "snmpOutTooBigs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 20],mutable: false,value: vec![]}), // Counter
                    snmpOutNoSuchNames: MibValue::intu32(mvintu32 {name: "snmpOutNoSuchNames".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 21],mutable: false,value: vec![]}), // Counter
                    snmpOutBadValues: MibValue::intu32(mvintu32 {name: "snmpOutBadValues".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 22],mutable: false,value: vec![]}), // Counter
                    snmpOutGenErrs: MibValue::intu32(mvintu32 {name: "snmpOutGenErrs".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 24],mutable: false,value: vec![]}), // Counter
                    snmpOutGetRequests: MibValue::intu32(mvintu32 {name: "snmpOutGetRequests".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 25],mutable: false,value: vec![]}), // Counter
                    snmpOutGetNexts: MibValue::intu32(mvintu32 {name: "snmpOutGetNexts".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 26],mutable: false,value: vec![]}), // Counter
                    snmpOutSetRequests: MibValue::intu32(mvintu32 {name: "snmpOutSetRequests".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 27],mutable: false,value: vec![]}), // Counter
                    snmpOutGetResponses: MibValue::intu32(mvintu32 {name: "snmpOutGetResponses".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 28],mutable: false,value: vec![]}), // Counter
                    snmpOutTraps: MibValue::intu32(mvintu32 {name: "snmpOutTraps".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 29],mutable: false,value: vec![]}), // Counter
                    snmpEnableAuthenTraps: MibValue::inti32(mvinti32 {name: "snmpEnableAuthenTraps".to_owned(), oid: vec![1, 3, 6, 1, 2, 1, 11, 30],mutable: true,value: vec![]}), // INTEGER
                },
            }
        }
    }

    
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    pub struct mvstring {
        pub name: String,
        pub oid: Vec<u16>,
        pub mutable: bool,
        pub value: Vec<String>,
    }
    
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    pub struct mvinti32 {
        pub name: String,
        pub oid: Vec<u16>,
        pub mutable: bool,
        pub value: Vec<i32>,
    }
    
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    pub struct mvintu32 {
        pub name: String,
        pub oid: Vec<u16>,
        pub mutable: bool,
        pub value: Vec<u32>,
    }
    
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    pub struct mvintu64 {
        pub name: String,
        pub oid: Vec<u16>,
        pub mutable: bool,
        pub value: Vec<u64>,
    }
    
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    pub struct mvoid {
        pub name: String,
        pub oid: Vec<u16>,
        pub mutable: bool,
        pub value: Vec<Vec<u8>>,
    }
    
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    pub struct mvipv4 {
        pub name: String,
        pub oid: Vec<u16>,
        pub mutable: bool,
        pub value: Vec<(u8, u8, u8, u8)>,
    }
    
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    pub struct mvmac {
        pub name: String,
        pub oid: Vec<u16>,
        pub mutable: bool,
        pub value: Vec<(u16, u16, u16, u16, u16, u16)>,
    }
    
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    pub struct mvipv6 {
            pub name: String,
            pub oid: Vec<u16>,
            pub mutable: bool,
            pub value: Vec<(u16, u16, u16, u16, u16, u16, u16, u16)>,
        }
    
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    pub enum MibValue {
        string(mvstring),
        inti32(mvinti32),
        intu32(mvintu32),
        intu64(mvintu64),
        oid(mvoid),
        ipv4(mvipv4),
        mac(mvmac),
        ipv6(mvipv6),
    }

    impl Clone for MibValue {
        fn clone(&self) -> Self {
            match self {
                MibValue::string(mvstring {
                    name,
                    oid,
                    mutable,
                    value,
                }) => MibValue::string(mvstring {
                    name: name.clone(),
                    oid: oid.to_owned(),
                    mutable: mutable.clone(),
                    value: value.to_owned(),
                }),
                MibValue::inti32(mvinti32 {
                    name,
                    oid,
                    mutable,
                    value,
                }) => MibValue::inti32(mvinti32 {
                    name: name.clone(),
                    oid: oid.to_owned(),
                    mutable: mutable.clone(),
                    value: value.to_owned(),
                }),
                MibValue::intu32(mvintu32 {
                    name,
                    oid,
                    mutable,
                    value,
                }) => MibValue::intu32(mvintu32 {
                    name: name.clone(),
                    oid: oid.to_owned(),
                    mutable: mutable.clone(),
                    value: value.to_owned(),
                }),
                MibValue::intu64(mvintu64 {
                    name,
                    oid,
                    mutable,
                    value,
                }) => MibValue::intu64(mvintu64 {
                    name: name.clone(),
                    oid: oid.to_owned(),
                    mutable: mutable.clone(),
                    value: value.to_owned(),
                }),
                MibValue::oid(mvoid {
                    name,
                    oid,
                    mutable,
                    value,
                }) => MibValue::oid(mvoid {
                    name: name.clone(),
                    oid: oid.to_owned(),
                    mutable: mutable.clone(),
                    value: value.to_owned(),
                }),
                MibValue::ipv4(mvipv4 {
                    name,
                    oid,
                    mutable,
                    value,
                }) => MibValue::ipv4(mvipv4 {
                    name: name.clone(),
                    oid: oid.to_owned(),
                    mutable: mutable.clone(),
                    value: value.to_owned(),
                }),
                MibValue::mac(mvmac {
                    name,
                    oid,
                    mutable,
                    value,
                }) => MibValue::mac(mvmac {
                    name: name.clone(),
                    oid: oid.to_owned(),
                    mutable: mutable.clone(),
                    value: value.to_owned(),
                }),
                MibValue::ipv6(mvipv6 {
                    name,
                    oid,
                    mutable,
                    value,
                }) => MibValue::ipv6(mvipv6 {
                    name: name.clone(),
                    oid: oid.to_owned(),
                    mutable: mutable.clone(),
                    value: value.to_owned(),
                }),
            }
        }
    }

    impl MibValue {
        fn clone_index(&self, index: usize) -> Self {
            match self {
                MibValue::string(mvstring) => MibValue::string(mvstring {
                    name: mvstring.name.clone(),
                    oid: mvstring.oid.to_owned(),
                    mutable: mvstring.mutable.clone(),
                    value: vec![mvstring.value.get(index).unwrap().to_owned()],
                }),
                MibValue::inti32(mvinti32) => MibValue::inti32(mvinti32 {
                    name: mvinti32.name.clone(),
                    oid: mvinti32.oid.to_owned(),
                    mutable: mvinti32.mutable.clone(),
                    value: vec![mvinti32.value.get(index).unwrap().to_owned()],
                }),
                MibValue::intu32(mvintu32) => MibValue::intu32(mvintu32 {
                    name: mvintu32.name.clone(),
                    oid: mvintu32.oid.to_owned(),
                    mutable: mvintu32.mutable.clone(),
                    value: vec![mvintu32.value.get(index).unwrap().to_owned()],
                }),
                MibValue::intu64(mvintu64) => MibValue::intu64(mvintu64 {
                    name: mvintu64.name.clone(),
                    oid: mvintu64.oid.to_owned(),
                    mutable: mvintu64.mutable.clone(),
                    value: vec![mvintu64.value.get(index).unwrap().to_owned()],
                }),
                MibValue::oid(mvoid) => MibValue::oid(mvoid {
                    name: mvoid.name.clone(),
                    oid: mvoid.oid.to_owned(),
                    mutable: mvoid.mutable.clone(),
                    value: vec![mvoid.value.get(index).unwrap().to_owned()],
                }),
                MibValue::ipv4(mvipv4) => MibValue::ipv4(mvipv4 {
                    name: mvipv4.name.clone(),
                    oid: mvipv4.oid.to_owned(),
                    mutable: mvipv4.mutable.clone(),
                    value: vec![mvipv4.value.get(index).unwrap().to_owned()],
                }),
                MibValue::mac(mvmac) => MibValue::mac(mvmac {
                    name: mvmac.name.clone(),
                    oid: mvmac.oid.to_owned(),
                    mutable: mvmac.mutable.clone(),
                    value: vec![mvmac.value.get(index).unwrap().to_owned()],
                }),
                MibValue::ipv6(mvipv6) => MibValue::ipv6(mvipv6 {
                    name: mvipv6.name.clone(),
                    oid: mvipv6.oid.to_owned(),
                    mutable: mvipv6.mutable.clone(),
                    value: vec![mvipv6.value.get(index).unwrap().to_owned()],
                }),
            }
        }
        
        fn has_oid(&self, noid: &[u16]) -> bool {
            match self {
                MibValue::string(mvstring {oid,..}) => noid == &oid[..],
                MibValue::inti32(mvinti32 {oid,..}) => noid == &oid[..],
                MibValue::intu32(mvintu32 {oid,..}) => noid == &oid[..],
                MibValue::intu64(mvintu64 {oid,..}) => noid == &oid[..],
                MibValue::oid(mvoid {oid,..}) => noid == &oid[..],
                MibValue::ipv4(mvipv4 {oid,..}) => noid == &oid[..],
                MibValue::mac(mvmac {oid,..}) => noid == &oid[..],
                MibValue::ipv6(mvipv6 {oid,..}) => noid == &oid[..],
                _ => false,
            }
        }
        pub fn get_oid(&self) -> Vec<u16> {
            match self {
                MibValue::string(mvstring {oid,..}) => oid.clone(),
                MibValue::inti32(mvinti32 {oid,..}) => oid.clone(),
                MibValue::intu32(mvintu32 {oid,..}) => oid.clone(),
                MibValue::intu64(mvintu64 {oid,..}) => oid.clone(),
                MibValue::oid(mvoid {oid,..}) => oid.clone(),
                MibValue::ipv4(mvipv4 {oid,..}) => oid.clone(),
                MibValue::mac(mvmac {oid,..}) => oid.clone(),
                MibValue::ipv6(mvipv6 {oid,..}) => oid.clone(),
            }
        }
        fn oid(&self) -> String {
            match self {
                MibValue::string(mvstring {oid,..}) => oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned(),
                MibValue::inti32(mvinti32 {oid,..}) => oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned(),
                MibValue::intu32(mvintu32 {oid,..}) => oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned(),
                MibValue::intu64(mvintu64 {oid,..}) => oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned(),
                MibValue::oid(mvoid {oid,..}) => oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned(),
                MibValue::ipv4(mvipv4 {oid,..}) => oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned(),
                MibValue::mac(mvmac {oid,..}) => oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned(),
                MibValue::ipv6(mvipv6 {oid,..}) => oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned(),
            }
        }
        fn egui_show(&self, app: &mut SnmpMonitorApp, ctx: &Context, ui: &mut Ui) {
            match self {
                MibValue::string(mvstring) => {
                    ui.collapsing(mvstring.name.clone(), |ui| match mvstring.value.len() {
                        1 => ui.label(mvstring.value.first().unwrap().to_string()),
                        _ => ui.spinner(),
                    });
                }
                MibValue::inti32(mvinti32) => {
                    ui.collapsing(mvinti32.name.clone(), |ui| match mvinti32.value.len() {
                        1 => ui
                            .label(mvinti32.value.first().unwrap().to_string())
                            .context_menu(|ui| self.add_plot_menu(app, ctx, ui, mvinti32.oid.clone())),
                        _ => ui.spinner(),
                    });
                }
                MibValue::intu32(mvintu32) => {
                    ui.collapsing(mvintu32.name.clone(), |ui| match mvintu32.value.len() {
                        1 => ui
                            .label(mvintu32.value.first().unwrap().to_string())
                            .context_menu(|ui| self.add_plot_menu(app, ctx, ui, mvintu32.oid.clone())),
                        _ => ui.spinner(),
                    });
                }
                MibValue::intu64(mvintu64) => {
                    ui.collapsing(mvintu64.name.clone(), |ui| match mvintu64.value.len() {
                        1 => ui
                            .label(mvintu64.value.first().unwrap().to_string())
                            .context_menu(|ui| self.add_plot_menu(app, ctx, ui, mvintu64.oid.clone())),
                        _ => ui.spinner(),
                    });
                }
                MibValue::oid(mvoid) => {
                    ui.collapsing(mvoid.name.clone(), |ui| match mvoid.value.len() {
                        1 => ui.label(format!("{:02x?}", mvoid.value.first().unwrap())),
                        _ => ui.spinner(),
                    });
                }
                MibValue::ipv4(mvipv4) => {
                    ui.collapsing(mvipv4.name.clone(), |ui| match mvipv4.value.len() {
                        1 => ui.label(format!("{:?}", mvipv4.value.first().unwrap())),
                        _ => ui.spinner(),
                    });
                }
                MibValue::mac(mvmac) => {
                    ui.collapsing(mvmac.name.clone(), |ui| match mvmac.value.len() {
                        1 => ui.label(format!("{:02x?}", mvmac.value.first().unwrap())),
                        _ => ui.spinner(),
                    });
                }
                MibValue::ipv6(mvipv6) => {
                    ui.collapsing(mvipv6.name.clone(), |ui| match mvipv6.value.len() {
                        1 => ui.label(format!("{:02x?}", mvipv6.value.first().unwrap())),
                        _ => ui.spinner(),
                    });
                }
            }
        }
        fn add_plot_menu(
            &self,
            app: &mut SnmpMonitorApp,
            ctx: &Context,
            ui: &mut Ui,
            oid: Vec<u16>,
        ) {
            match self {
                MibValue::inti32(mvinti32) => {
                    if !app.context.plots.is_empty() {
                        ui.menu_button("add to existing plot", |ui| {
                            let _ = app.context.plots.clone().into_iter().for_each(|plot| {
                                // println!("{}", plot.0);
                                if ui.button(plot.0.clone()).clicked() {
                                    println!("{} button clicked", plot.0);
                                    app.new_plot_window_manager.value_to_add = Some(self.clone());

                                    let snmp_log: Vec<MibObject> = BufReader::new(File::open(format!("MIB-log.log")).unwrap())
                                                                        .lines()
                                                                        .map(|line| line.unwrap())
                                                                        .filter(|line| line != "")
                                                                        .map(|line| serde_json::from_str::<MibObject>(&line).unwrap())
                                                                        .collect::<Vec<MibObject>>();
            
                                    
                                    app.context
                                        .plots
                                        .get_mut(&plot.0.clone())
                                        .unwrap()
                                        .plottables
                                        .push(Plottable::new(self.clone()).unwrap());

                                    snmp_log.into_iter().for_each(|obj| {
                                        println!("{:?}", app.new_plot_window_manager.value_to_add.clone().expect("couldnt clone oid").get_oid());
                                        app.context.plots.get_mut(&plot.0.clone()).unwrap().plottables.last_mut().unwrap().add((obj.timestamp, obj.find_oid(app.new_plot_window_manager.value_to_add.clone().expect("couldnt clone oid").get_oid()).expect("couldnt find object by oid").val_as_mvinti64().expect("couldnt convert value to mvinti64").first().expect("no first value in vector").clone() ));
                                    });

                                    ui.close_menu();
                                };
                            });
                        });
                    }
                    if ui.button("create new plot").clicked() {
                        println!("create new plot button clicked");
                        app.new_plot_window_manager.value_to_add = Some(self.clone());
                        app.new_plot_window_manager.show = true;
                        app.new_plot_window_manager.open = true;
                        ui.close_menu();
                    };
                },
                MibValue::intu32(mvintu32) => {
                    if !app.context.plots.is_empty() {
                        ui.menu_button("add to existing plot", |ui| {
                            let _ = app.context.plots.clone().into_iter().for_each(|plot| {
                                // println!("{}", plot.0);
                                if ui.button(plot.0.clone()).clicked() {
                                    println!("{} button clicked", plot.0);
                                    app.new_plot_window_manager.value_to_add = Some(self.clone());

                                    let snmp_log: Vec<MibObject> = BufReader::new(File::open(format!("MIB-log.log")).unwrap())
                                                                        .lines()
                                                                        .map(|line| line.unwrap())
                                                                        .filter(|line| line != "")
                                                                        .map(|line| serde_json::from_str::<MibObject>(&line).unwrap())
                                                                        .collect::<Vec<MibObject>>();
            
                                    
                                    app.context
                                        .plots
                                        .get_mut(&plot.0.clone())
                                        .unwrap()
                                        .plottables
                                        .push(Plottable::new(self.clone()).unwrap());

                                    snmp_log.into_iter().for_each(|obj| {
                                        println!("{:?}", app.new_plot_window_manager.value_to_add.clone().expect("couldnt clone oid").get_oid());
                                        app.context.plots.get_mut(&plot.0.clone()).unwrap().plottables.last_mut().unwrap().add((obj.timestamp, obj.find_oid(app.new_plot_window_manager.value_to_add.clone().expect("couldnt clone oid").get_oid()).expect("couldnt find object by oid").val_as_mvinti64().expect("couldnt convert value to mvinti64").first().expect("no first value in vector").clone() ));
                                    });

                                    ui.close_menu();
                                };
                            });
                        });
                    }
                    if ui.button("create new plot").clicked() {
                        println!("create new plot button clicked");
                        app.new_plot_window_manager.value_to_add = Some(self.clone());
                        app.new_plot_window_manager.show = true;
                        app.new_plot_window_manager.open = true;
                        ui.close_menu();
                    };
                },
                MibValue::intu64(mvintu64) => {
                    if !app.context.plots.is_empty() {
                        ui.menu_button("add to existing plot", |ui| {
                            let _ = app.context.plots.clone().into_iter().for_each(|plot| {
                                // println!("{}", plot.0);
                                if ui.button(plot.0.clone()).clicked() {
                                    println!("{} button clicked", plot.0);
                                    app.new_plot_window_manager.value_to_add = Some(self.clone());

                                    let snmp_log: Vec<MibObject> = BufReader::new(File::open(format!("MIB-log.log")).unwrap())
                                                                        .lines()
                                                                        .map(|line| line.unwrap())
                                                                        .filter(|line| line != "")
                                                                        .map(|line| serde_json::from_str::<MibObject>(&line).unwrap())
                                                                        .collect::<Vec<MibObject>>();
            
                                    
                                    app.context
                                        .plots
                                        .get_mut(&plot.0.clone())
                                        .unwrap()
                                        .plottables
                                        .push(Plottable::new(self.clone()).unwrap());

                                    snmp_log.into_iter().for_each(|obj| {
                                        println!("{:?}", app.new_plot_window_manager.value_to_add.clone().expect("couldnt clone oid").get_oid());
                                        app.context.plots.get_mut(&plot.0.clone()).unwrap().plottables.last_mut().unwrap().add((obj.timestamp, obj.find_oid(app.new_plot_window_manager.value_to_add.clone().expect("couldnt clone oid").get_oid()).expect("couldnt find object by oid").val_as_mvinti64().expect("couldnt convert value to mvinti64").first().expect("no first value in vector").clone() ));
                                    });

                                    ui.close_menu();
                                };
                            });
                        });
                    }
                    if ui.button("create new plot").clicked() {
                        println!("create new plot button clicked");
                        app.new_plot_window_manager.value_to_add = Some(self.clone());
                        app.new_plot_window_manager.show = true;
                        app.new_plot_window_manager.open = true;
                        ui.close_menu();
                    };
                },
                _ => {},
            }
        }
        async fn walk(&mut self, client: &Snmp2cClient) -> Option<String> {
            match self {
                MibValue::string(mvstring {
                    name,
                    oid,
                    mutable,
                    value,
                }) => {
                    match ObjectIdentifier::from_str(&oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned()) {
                        Ok(res) => {
                            match client.walk_bulk(res, 100).await {
                                Ok(res) => {
                                    *value = res
                                        .into_iter()
                                        .map(|a| match a.1.as_bytes() {
                                            Some(res) => match String::from_utf8(res.to_owned()) {
                                                Ok(res) => res,
                                                Err(_) => "err".to_owned(),
                                            },
                                            None => "err".to_owned(),
                                        })
                                        .collect::<Vec<String>>();
                                    return None;
                                }
                                Err(_) => {
                                    return Some("error completing snmp walk".to_owned());
                                }
                            };
                        }
                        Err(_) => {
                            return Some("error creating oid from string".to_owned());
                        }
                    };
                }
                MibValue::inti32(mvinti32 {
                    name,
                    oid,
                    mutable,
                    value,
                }) => {
                    match ObjectIdentifier::from_str(&oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned()) {
                        Ok(res) => {
                            match client.walk_bulk(res, 100).await {
                                Ok(res) => {
                                    *value = res
                                        .into_iter()
                                        .map(|a| match a.1.as_i32() {
                                            Some(res) => res,
                                            None => 0,
                                        })
                                        .collect::<Vec<i32>>();
                                    return None;
                                }
                                Err(_) => {
                                    return Some("error completing snmp walk".to_owned());
                                }
                            };
                        }
                        Err(_) => {
                            return Some("error creating oid from string".to_owned());
                        }
                    };
                }
                MibValue::intu32(mvintu32 {
                    name,
                    oid,
                    mutable,
                    value,
                }) => {
                    match ObjectIdentifier::from_str(&oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned()) {
                        Ok(res) => {
                            match client.walk_bulk(res, 100).await {
                                Ok(res) => {
                                    *value = res
                                        .into_iter()
                                        .map(|a| match a.1.as_u32() {
                                            Some(res) => res,
                                            None => 0,
                                        })
                                        .collect::<Vec<u32>>();
                                    return None;
                                }
                                Err(_) => {
                                    return Some("error completing snmp walk".to_owned());
                                }
                            };
                        }
                        Err(_) => {
                            return Some("error creating oid from string".to_owned());
                        }
                    };
                }
                MibValue::intu64(mvintu64 {
                    name,
                    oid,
                    mutable,
                    value,
                }) => {
                    match ObjectIdentifier::from_str(&oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned()) {
                        Ok(res) => {
                            match client.walk_bulk(res, 100).await {
                                Ok(res) => {
                                    *value = res
                                        .into_iter()
                                        .map(|a| match a.1.as_u64() {
                                            Some(res) => res,
                                            None => 0,
                                        })
                                        .collect::<Vec<u64>>();
                                    return None;
                                }
                                Err(_) => {
                                    return Some("error completing snmp walk".to_owned());
                                }
                            };
                        }
                        Err(_) => {
                            return Some("error creating oid from string".to_owned());
                        }
                    };
                }
                MibValue::oid(mvoid {
                    name,
                    oid,
                    mutable,
                    value,
                }) => {
                    match ObjectIdentifier::from_str(&oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned()) {
                        Ok(res) => {
                            match client.walk_bulk(res, 100).await {
                                Ok(res) => {
                                    *value = res
                                        .into_iter()
                                        .map(|a| match a.1.as_oid() {
                                            Some(res) => res
                                                .as_slice()
                                                .to_vec()
                                                .into_iter()
                                                .map(|a| a as u8)
                                                .collect::<Vec<u8>>(),
                                            None => vec![],
                                        })
                                        .collect::<Vec<Vec<u8>>>();
                                    return None;
                                }
                                Err(_) => {
                                    return Some("error completing snmp walk".to_owned());
                                }
                            };
                        }
                        Err(_) => {
                            return Some("error creating oid from string".to_owned());
                        }
                    };
                }
                MibValue::ipv4(mvipv4 {
                    name,
                    oid,
                    mutable,
                    value,
                }) => {
                    match ObjectIdentifier::from_str(&oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned()) {
                        Ok(res) => {
                            match client.walk_bulk(res, 100).await {
                                Ok(res) => {
                                    *value = res
                                        .into_iter()
                                        .map(|a| {
                                            // println!("ipv4 res: \n{:?}, {:?}", a.1, a.1.as_ipv4());
                                            match a.1.as_ipv4() {
                                                Some(res) => {
                                                    let c = res.octets();
                                                    if c.len() == 4 {
                                                        return (c[0], c[1], c[2], c[3]);
                                                    } else {
                                                        return (0, 0, 0, 0);
                                                    }
                                                }
                                                None => return (0, 0, 0, 0),
                                            };
                                        })
                                        .collect::<Vec<(u8, u8, u8, u8)>>();
                                    return None;
                                }
                                Err(_) => {
                                    return Some("error completing snmp walk".to_owned());
                                }
                            };
                        }
                        Err(_) => {
                            return Some("error creating oid from string".to_owned());
                        }
                    };
                }
                MibValue::mac(mvmac {
                    name,
                    oid,
                    mutable,
                    value,
                }) => {
                    match ObjectIdentifier::from_str(&oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned()) {
                        Ok(res) => {
                            match client.walk_bulk(res, 100).await {
                                Ok(res) => {
                                    *value = res
                                        .into_iter()
                                        .map(|a| match a.1.as_bytes() {
                                            Some(res) => {
                                                // println!("mac res: {:?}", res);
                                                let c = match String::from_utf8(res.to_owned()) {
                                                    Ok(res) => res
                                                        .split(".")
                                                        .into_iter()
                                                        .map(|b| match b.parse::<u16>() {
                                                            Ok(e) => e,
                                                            Err(_) => 0,
                                                        })
                                                        .collect::<Vec<u16>>(),
                                                    Err(_) => vec![0, 0, 0, 0, 0, 0],
                                                };
                                                if c.len() == 6 {
                                                    (c[0], c[1], c[2], c[3], c[4], c[5])
                                                } else {
                                                    (0, 0, 0, 0, 0, 0)
                                                }
                                            }
                                            None => (0, 0, 0, 0, 0, 0),
                                        })
                                        .collect::<Vec<(u16, u16, u16, u16, u16, u16)>>();
                                    return None;
                                }
                                Err(_) => {
                                    return Some("error completing snmp walk".to_owned());
                                }
                            };
                        }
                        Err(_) => {
                            return Some("error creating oid from string".to_owned());
                        }
                    };
                }
                MibValue::ipv6(mvipv6 {
                    name,
                    oid,
                    mutable,
                    value,
                }) => {
                    match ObjectIdentifier::from_str(&oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned()) {
                        Ok(res) => {
                            match client.walk_bulk(res, 100).await {
                                Ok(res) => {
                                    *value = res
                                        .into_iter()
                                        .map(|a| match a.1.as_bytes() {
                                            Some(res) => {
                                                // println!("ipv6 res: {:?}", res);
                                                let c = match String::from_utf8(res.to_owned()) {
                                                    Ok(res) => res
                                                        .split(".")
                                                        .into_iter()
                                                        .map(|b| match b.parse::<u16>() {
                                                            Ok(e) => e,
                                                            Err(_) => 0,
                                                        })
                                                        .collect::<Vec<u16>>(),
                                                    Err(_) => vec![0, 0, 0, 0, 0, 0, 0, 0],
                                                };
                                                if c.len() == 8 {
                                                    (c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7])
                                                } else {
                                                    (0, 0, 0, 0, 0, 0, 0, 0)
                                                }
                                            }
                                            None => (0, 0, 0, 0, 0, 0, 0, 0),
                                        })
                                        .collect::<Vec<(u16, u16, u16, u16, u16, u16, u16, u16)>>();
                                    return None;
                                }
                                Err(_) => {
                                    return Some("error completing snmp walk".to_owned());
                                }
                            };
                        }
                        Err(_) => {
                            return Some("error creating oid from string".to_owned());
                        }
                    };
                }
            }
        }
        pub fn as_mvstring(&self) -> Option<mvstring> {
            match self {
                MibValue::string(mvstring) => Some(mvstring { name: mvstring.name.clone(), oid: mvstring.oid.clone(), mutable: mvstring.mutable.clone(), value: mvstring.value.clone() }),
                _ => None,
            }
        }
        pub fn as_mvinti32(&self) -> Option<mvinti32> {
            match self {
                MibValue::inti32(mvinti32) => Some(mvinti32 { name: mvinti32.name.clone(), oid: mvinti32.oid.clone(), mutable: mvinti32.mutable.clone(), value: mvinti32.value.clone() }),
                _ => None,
            }
        }
        pub fn val_as_mvinti64(&self) -> Option<Vec<i64>> {
            match self {
                MibValue::inti32(mvinti32) => Some(mvinti32.value.clone().into_iter().map(|int| int as i64).collect::<Vec<i64>>()),
                MibValue::intu32(mvintu32) => Some(mvintu32.value.clone().into_iter().map(|int| int as i64).collect::<Vec<i64>>()),
                MibValue::intu64(mvintu64) => Some(mvintu64.value.clone().into_iter().map(|int| int as i64).collect::<Vec<i64>>()),
                _ => None,
            }
        }
        pub fn as_mvintu32(&self) -> Option<mvintu32> {
            match self {
                MibValue::intu32(mvintu32) => Some(mvintu32 { name: mvintu32.name.clone(), oid: mvintu32.oid.clone(), mutable: mvintu32.mutable.clone(), value: mvintu32.value.clone() }),
                _ => None,
            }
        }
        pub fn as_mvintu64(&self) -> Option<mvintu64> {
            match self {
                MibValue::intu64(mvintu64) => Some(mvintu64 { name: mvintu64.name.clone(), oid: mvintu64.oid.clone(), mutable: mvintu64.mutable.clone(), value: mvintu64.value.clone() }),
                _ => None,
            }
        }
        pub fn as_mvoid(&self) -> Option<mvoid> {
            match self {
                MibValue::oid(mvoid) => Some(mvoid { name: mvoid.name.clone(), oid: mvoid.oid.clone(), mutable: mvoid.mutable.clone(), value: mvoid.value.clone() }),
                _ => None,
            }
        }
        pub fn as_mvipv4(&self) -> Option<mvipv4> {
            match self {
                MibValue::ipv4(mvipv4) => Some(mvipv4 { name: mvipv4.name.clone(), oid: mvipv4.oid.clone(), mutable: mvipv4.mutable.clone(), value: mvipv4.value.clone() }),
                _ => None,
            }
        }
        pub fn as_mvmac(&self) -> Option<mvmac> {
            match self {
                MibValue::mac(mvmac) => Some(mvmac { name: mvmac.name.clone(), oid: mvmac.oid.clone(), mutable: mvmac.mutable.clone(), value: mvmac.value.clone() }),
                _ => None,
            }
        }
        pub fn as_mvipv6(&self) -> Option<mvipv6> {
            match self {
                MibValue::ipv6(mvipv6) => Some(mvipv6 { name: mvipv6.name.clone(), oid: mvipv6.oid.clone(), mutable: mvipv6.mutable.clone(), value: mvipv6.value.clone() }),
                _ => None,
            }
        }
    }
}
