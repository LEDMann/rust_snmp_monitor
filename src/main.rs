#![allow(non_snake_case, non_camel_case_types)]

use std::collections::HashMap;
use std::str::FromStr;
use std::net::{IpAddr, SocketAddr};

use std::sync::mpsc::{Sender, Receiver};
use std::time::Duration;
use async_trait::async_trait;
use csv::Error;
use tokio::runtime::Builder;
use tokio::{task, time};

use eframe::{egui, AppCreator};

use csnmp::{Snmp2cClient, ObjectValue, client, ObjectIdentifier};

struct SnmpMonitorApp {
    name: String,
    target_ip: IpAddr,
    community: String,
    reciever: Receiver<MibObject>,
    object: Option<MibObject>,
}


impl MibObject {
    async fn walk(&mut self, client: &Snmp2cClient) {
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
}

impl Clone for MibObject {
    fn clone(&self) -> Self {
        MibObject {
            oid: self.oid.to_owned(), 
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

struct MibObject {
    oid: Vec<u16>, 
    system: System, 
    interfaces: Interfaces, 
    at: At, 
    ip: Ip, 
    icmp: Icmp, 
    tcp: Tcp, 
    udp: Udp, 
    egp: Egp, 
    transmission: MibString, 
    snmp: Snmp, 
}


impl System {
    async fn walk(&mut self, client: &Snmp2cClient) {
        self.sysDesc.walk(client).await;
        self.sysObjectID.walk(client).await;
        self.sysUpTime.walk(client).await;
        self.sysContact.walk(client).await;
        self.sysName.walk(client).await;
        self.sysLocation.walk(client).await;
        self.sysServices.walk(client).await;
    }
}

impl Clone for System {
    fn clone(&self) -> Self {
        System {
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

struct System { 
    sysDesc: MibString, 
    sysObjectID: oid, 
    sysUpTime: intu32, 
    sysContact: MibString, 
    sysName: MibString, 
    sysLocation: MibString, 
    sysServices: inti32, 
}

impl Interfaces {
    async fn walk(&mut self, client: &Snmp2cClient) {
        self.ifNumber.walk(client).await;
        self.ifTable.walk(client).await;
    }
}

impl Clone for Interfaces {
    fn clone(&self) -> Self {
        Interfaces {
            ifNumber: self.ifNumber.clone(), 
            ifTable: self.ifTable.clone(), 
        }
    }
}

struct Interfaces { 
    ifNumber: inti32, 
    ifTable: IfTable, 
}

impl IfTable {
    async fn walk(&mut self, client: &Snmp2cClient) {
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
}

impl Clone for IfTable {
    fn clone(&self) -> Self {
        IfTable {
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

struct IfTable { 
    ifIndex:           inti32, 
    ifDescr:           MibString, 
    ifType:            inti32, 
    ifMtu:             inti32, 
    ifSpeed:           intu32, 
    ifPhysAddress:     ipv6, 
    ifAdminStatus:     inti32, 
    ifOperStatus:      inti32, 
    ifLastChange:      intu32, 
    ifInOctets:        intu32, 
    ifInUcastPkts:     intu32, 
    ifInNUcastPkts:    intu32, 
    ifInDiscards:      intu32, 
    ifInErrors:        intu32, 
    ifInUnknownProtos: intu32, 
    ifOutOctets:       intu32, 
    ifOutUcastPkts:    intu32, 
    ifOutNUcastPkts:   intu32, 
    ifOutDiscards:     intu32, 
    ifOutErrors:       intu32, 
    ifOutQLen:         intu32, 
    ifSpecific:        oid, 
}

impl At {
    async fn walk(&mut self, client: &Snmp2cClient) {
        self.atTable.walk(client).await;
    }
}

impl Clone for At {
    fn clone(&self) -> Self {
        At {
            atTable: self.atTable.clone(), 
        }
    }
}

struct At {
    atTable: AtTable, 
}

impl AtTable {
    async fn walk(&mut self, client: &Snmp2cClient) {
        self.atIfIndex.walk(client).await;
        self.atPhysAddress.walk(client).await;
        self.atNetAddress.walk(client).await;
    }
}

impl Clone for AtTable {
    fn clone(&self) -> Self {
        AtTable {
            atIfIndex: self.atIfIndex.clone(), 
            atPhysAddress: self.atPhysAddress.clone(), 
            atNetAddress: self.atNetAddress.clone(), 
        }
    }
}

struct AtTable { 
    atIfIndex:     inti32, 
    atPhysAddress: ipv6, 
    atNetAddress:  MibString, 
}

impl Ip {
    async fn walk(&mut self, client: &Snmp2cClient) {
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
}

impl Clone for Ip {
    fn clone(&self) -> Self {
        Ip {
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

struct Ip { 
    ipForwarding:      inti32, 
    ipDefaultTTL:      inti32, 
    ipInReceives:      intu32, 
    ipInHdrErrors:     intu32, 
    ipInAddrErrors:    intu32, 
    ipForwDatagrams:   intu32, 
    ipInUnknownProtos: intu32, 
    ipInDiscards:      intu32, 
    ipInDelivers:      intu32, 
    ipOutRequests:     intu32, 
    ipOutDiscards:     intu32, 
    ipOutNoRoutes:     intu32, 
    ipReasmTimeout:    inti32, 
    ipReasmReqds:      intu32, 
    ipReasmOKs:        intu32, 
    ipReasmFails:      intu32, 
    ipFragOKs:         intu32, 
    ipFragFails:       intu32, 
    ipFragCreates:     intu32, 
    ipAddrTable:       IpAddrTable, 
    ipRouteTable:      IpRouteTable, 
    ipNetToMediaTable: IpNetToMediaTable, 
    ipRoutingDiscards: inti32, 
}

impl IpAddrTable {
    async fn walk(&mut self, client: &Snmp2cClient) {
        self.ipAdEntAddr.walk(client).await;
        self.ipAdEntIfIndex.walk(client).await;
        self.ipAdEntNetMask.walk(client).await;
        self.ipAdEntBcastAddr.walk(client).await;
        self.ipAdEntReasmMaxSize.walk(client).await;
    }
}

impl Clone for IpAddrTable {
    fn clone(&self) -> Self {
        IpAddrTable {
            ipAdEntAddr: self.ipAdEntAddr.clone(), 
            ipAdEntIfIndex: self.ipAdEntIfIndex.clone(), 
            ipAdEntNetMask: self.ipAdEntNetMask.clone(), 
            ipAdEntBcastAddr: self.ipAdEntBcastAddr.clone(), 
            ipAdEntReasmMaxSize: self.ipAdEntReasmMaxSize.clone(), 
        }
    }
}

struct IpAddrTable { 
    ipAdEntAddr:         MibString  , 
    ipAdEntIfIndex:      inti32, 
    ipAdEntNetMask:      MibString  , 
    ipAdEntBcastAddr:    inti32, 
    ipAdEntReasmMaxSize: inti32, 
}

impl IpRouteTable {
    async fn walk(&mut self, client: &Snmp2cClient) {
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
}

impl Clone for IpRouteTable {
    fn clone(&self) -> Self {
        IpRouteTable {
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

struct IpRouteTable { 
    ipRouteDest:    MibString  , 
    ipRouteIfIndex: inti32, 
    ipRouteMetric1: inti32, 
    ipRouteMetric2: inti32, 
    ipRouteMetric3: inti32, 
    ipRouteMetric4: inti32, 
    ipRouteNextHop: MibString  , 
    ipRouteType:    inti32, 
    ipRouteProto:   inti32, 
    ipRouteAge:     inti32, 
    ipRouteMask:    MibString  , 
    ipRouteMetric5: inti32, 
    ipRouteInfo:    oid   , 
}

impl IpNetToMediaTable {
    async fn walk(&mut self, client: &Snmp2cClient) {
        self.ipNetToMediaIfIndex.walk(client).await;
        self.ipNetToMediaPhysAddress.walk(client).await;
        self.ipNetToMediaNetAddress.walk(client).await;
        self.ipNetToMediaType.walk(client).await;
    }
}

impl Clone for IpNetToMediaTable {
    fn clone(&self) -> Self {
        IpNetToMediaTable {
            ipNetToMediaIfIndex: self.ipNetToMediaIfIndex.clone(), 
            ipNetToMediaPhysAddress: self.ipNetToMediaPhysAddress.clone(), 
            ipNetToMediaNetAddress: self.ipNetToMediaNetAddress.clone(), 
            ipNetToMediaType: self.ipNetToMediaType.clone(), 
        }
    }
}

struct IpNetToMediaTable { 
    ipNetToMediaIfIndex:     inti32, 
    ipNetToMediaPhysAddress: ipv6   , 
    ipNetToMediaNetAddress:  MibString  , 
    ipNetToMediaType:        inti32, 
}

impl Icmp {
    async fn walk(&mut self, client: &Snmp2cClient) {
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
}

impl Clone for Icmp {
    fn clone(&self) -> Self {
        Icmp {
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

struct Icmp { 
    icmpInMsgs:           inti32, 
    icmpInErrors:         inti32, 
    icmpInDestUnreachs:   inti32, 
    icmpInTimeExcds:      inti32, 
    icmpInParmProbs:      inti32, 
    icmpInSrcQuenchs:     inti32, 
    icmpInRedirects:      inti32, 
    icmpInEchos:          inti32, 
    icmpInEchoReps:       inti32, 
    icmpInTimestamps:     inti32, 
    icmpInTimestampReps:  inti32, 
    icmpInAddrMasks:      inti32, 
    icmpInAddrMaskReps:   inti32, 
    icmpOutMsgs:          inti32, 
    icmpOutErrors:        inti32, 
    icmpOutDestUnreachs:  inti32, 
    icmpOutTimeExcds:     inti32, 
    icmpOutParmProbs:     inti32, 
    icmpOutSrcQuenchs:    inti32, 
    icmpOutRedirects:     inti32, 
    icmpOutEchos:         inti32, 
    icmpOutEchoReps:      inti32, 
    icmpOutTimestamps:    inti32, 
    icmpOutTimestampReps: inti32, 
    icmpOutAddrMasks:     inti32, 
    icmpOutAddrMaskReps:  inti32, 
}

impl Tcp {
    async fn walk(&mut self, client: &Snmp2cClient) {
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
}

impl Clone for Tcp {
    fn clone(&self) -> Self {
        Tcp {
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

struct Tcp { 
    tcpRtoAlgorithm: inti32, 
    tcpRtoMin:       inti32, 
    tcpRtoMax:       inti32, 
    tcpMaxConn:      inti32, 
    tcpActiveOpens:  intu32, 
    tcpPassiveOpens: intu32, 
    tcpAttemptFails: intu32, 
    tcpEstabResets:  intu32, 
    tcpCurrEstab:    intu32, 
    tcpInSegs:       intu32, 
    tcpOutSegs:      intu32, 
    tcpRetransSegs:  intu32, 
    tcpConnTable:    TcpConnTable, 
    tcpInErrs:       intu32, 
    tcpOutRsts:      intu32, 
}

impl TcpConnTable {
    async fn walk(&mut self, client: &Snmp2cClient) {
        self.tcpConnState.walk(client).await;
        self.tcpConnLocalAddress.walk(client).await;
        self.tcpConnLocalPort.walk(client).await;
        self.tcpConnRemAddress.walk(client).await;
        self.tcpConnRemPort.walk(client).await;
    }
}

impl Clone for TcpConnTable {
    fn clone(&self) -> Self {
        TcpConnTable {
            tcpConnState: self.tcpConnState.clone(), 
            tcpConnLocalAddress: self.tcpConnLocalAddress.clone(), 
            tcpConnLocalPort: self.tcpConnLocalPort.clone(), 
            tcpConnRemAddress: self.tcpConnRemAddress.clone(), 
            tcpConnRemPort: self.tcpConnRemPort.clone(), 
        }
    }
}

struct TcpConnTable { 
    tcpConnState:        inti32, 
    tcpConnLocalAddress: MibString  , 
    tcpConnLocalPort:    inti32, 
    tcpConnRemAddress:   MibString  , 
    tcpConnRemPort:      inti32, 
}

impl Udp {
    async fn walk(&mut self, client: &Snmp2cClient) {
        self.udpInDatagrams.walk(client).await;
        self.udpNoPorts.walk(client).await;
        self.udpInErrors.walk(client).await;
        self.udpOutDatagrams.walk(client).await;
        self.udpTable.walk(client).await;
    }
}

impl Clone for Udp {
    fn clone(&self) -> Self {
        Udp {
            udpInDatagrams: self.udpInDatagrams.clone(), 
            udpNoPorts: self.udpNoPorts.clone(), 
            udpInErrors: self.udpInErrors.clone(), 
            udpOutDatagrams: self.udpOutDatagrams.clone(), 
            udpTable: self.udpTable.clone(), 
        }
    }
}

struct Udp { 
    udpInDatagrams:  intu32, 
    udpNoPorts:      intu32, 
    udpInErrors:     intu32, 
    udpOutDatagrams: intu32, 
    udpTable:        UdpTable, 
}

impl UdpTable {
    async fn walk(&mut self, client: &Snmp2cClient) {
        self.udpLocalAddress.walk(client).await;
        self.udpLocalPort.walk(client).await;
    }
}

impl Clone for UdpTable {
    fn clone(&self) -> Self {
        UdpTable {
            udpLocalAddress: self.udpLocalAddress.clone(), 
            udpLocalPort: self.udpLocalPort.clone(), 
        }
    }
}

struct UdpTable { 
    udpLocalAddress: MibString  , 
    udpLocalPort:    inti32, 
}

impl Egp {
    async fn walk(&mut self, client: &Snmp2cClient) {
        self.egpInMsgs.walk(client).await;
        self.egpInErrors.walk(client).await;
        self.egpOutMsgs.walk(client).await;
        self.egpOutErrors.walk(client).await;
        self.egpNeighTable.walk(client).await;
        self.egpAs.walk(client).await;
    }
}

impl Clone for Egp {
    fn clone(&self) -> Self {
        Egp {
            egpInMsgs: self.egpInMsgs.clone(), 
            egpInErrors: self.egpInErrors.clone(), 
            egpOutMsgs: self.egpOutMsgs.clone(), 
            egpOutErrors: self.egpOutErrors.clone(), 
            egpNeighTable: self.egpNeighTable.clone(), 
            egpAs: self.egpAs.clone(), 
        }
    }
}

struct Egp { 
    egpInMsgs:     intu32, 
    egpInErrors:   intu32, 
    egpOutMsgs:    intu32, 
    egpOutErrors:  intu32, 
    egpNeighTable: EgpNeighTable, 
    egpAs:         inti32, 
}

impl EgpNeighTable {
    async fn walk(&mut self, client: &Snmp2cClient) {
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
}

impl Clone for EgpNeighTable {
    fn clone(&self) -> Self {
        EgpNeighTable {
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

struct EgpNeighTable { 
    egpNeighState:         inti32, 
    egpNeighAddr:          MibString  , 
    egpNeighAs:            inti32, 
    egpNeighInMsgs:        intu32, 
    egpNeighInErrs:        intu32, 
    egpNeighOutMsgs:       intu32, 
    egpNeighOutErrs:       intu32, 
    egpNeighInErrMsgs:     intu32, 
    egpNeighOutErrMsgs:    intu32, 
    egpNeighStateUps:      intu32, 
    egpNeighStateDowns:    intu32, 
    egpNeighIntervalHello: inti32, 
    egpNeighIntervalPoll:  inti32, 
    egpNeighMode:          inti32, 
    egpNeighEventTrigger:  inti32, 
}

impl Snmp {
    async fn walk(&mut self, client: &Snmp2cClient) {
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
}

impl Clone for Snmp {
    fn clone(&self) -> Self {
        Snmp {
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

struct Snmp { 
    snmpInPkts:              intu32, 
    snmpOutPkts:             intu32, 
    snmpInBadVersions:       intu32, 
    snmpInBadCommunityNames: intu32, 
    snmpInBadCommunityUses:  intu32, 
    snmpInASNParseErrs:      intu32, 
    snmpInTooBigs:           intu32, 
    snmpInNoSuchNames:       intu32, 
    snmpInBadValues:         intu32, 
    snmpInReadOnlys:         intu32, 
    snmpInGenErrs:           intu32, 
    snmpInTotalReqVars:      intu32, 
    snmpInTotalSetVars:      intu32, 
    snmpInGetRequests:       intu32, 
    snmpInGetNexts:          intu32, 
    snmpInSetRequests:       intu32, 
    snmpInGetResponses:      intu32, 
    snmpInTraps:             intu32, 
    snmpOutTooBigs:          intu32, 
    snmpOutNoSuchNames:      intu32, 
    snmpOutBadValues:        intu32, 
    snmpOutGenErrs:          intu32, 
    snmpOutGetRequests:      intu32, 
    snmpOutGetNexts:         intu32, 
    snmpOutSetRequests:      intu32, 
    snmpOutGetResponses:     intu32, 
    snmpOutTraps:            intu32, 
    snmpEnableAuthenTraps:   inti32 
} 

#[async_trait]
trait MibValue {
    fn oid(&self) -> String;
    async fn walk(&mut self, client: &Snmp2cClient)-> Option<String>;
}

struct MibString {
    name: String,
    oid: Vec<u8>,
    mutable: bool,
    value: Vec<String>
}

#[async_trait]
impl MibValue for MibString {
    fn oid(&self) -> String {
        return self.oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned();
    }
    async fn walk(&mut self, client: &Snmp2cClient) -> Option<String> {
        match ObjectIdentifier::from_str(&self.oid()) {
            Ok(res) => {
                match client.walk_bulk(res, 100).await {
                    Ok(res) => {
                        self.value = res.into_iter().map(|a| 
                            match a.1.as_bytes() {
                                Some(res) => match String::from_utf8(res.to_owned()) {
                                    Ok(res) => res,
                                    Err(_) => "err".to_owned(),
                                },
                                None => "err".to_owned(),
                            }
                        ).collect::<Vec<String>>();
                        return None;
                    },
                    Err(_) => {
                        return Some("error completing snmp walk".to_owned());
                    },
                };
            }
            Err(_) => {
                return Some("error creating oid from string".to_owned());
            }
        };
    }
}

impl Clone for MibString {
    fn clone(&self) -> Self {
        MibString { 
            name:    self.name.clone(), 
            oid:     self.oid.to_owned(), 
            mutable: self.mutable.clone(), 
            value:   self.value.to_owned() 
        }
    }
}


struct inti32 {
    name: String,
    oid: Vec<u8>,
    mutable: bool,
    value: Vec<i32>
}

#[async_trait]
impl MibValue for inti32 {
    fn oid(&self) -> String {
        return self.oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned();
    }
    async fn walk(&mut self, client: &Snmp2cClient) -> Option<String> {
        match ObjectIdentifier::from_str(&self.oid()) {
            Ok(res) => {
                match client.walk_bulk(res, 100).await {
                    Ok(res) => {
                        self.value = res.into_iter().map(|a| 
                            match a.1.as_i32() {
                                Some(res) => res,
                                None => 0,
                            }
                        ).collect::<Vec<i32>>();
                        return None;
                    },
                    Err(_) => {
                        return Some("error completing snmp walk".to_owned());
                    },
                };
            }
            Err(_) => {
                return Some("error creating oid from string".to_owned());
            }
        };
    }
}

impl Clone for inti32 {
    fn clone(&self) -> Self {
        inti32 { 
            name:    self.name.clone(), 
            oid:     self.oid.to_owned(), 
            mutable: self.mutable.clone(), 
            value:   self.value.to_owned() 
        }
    }
}

struct intu32 {
    name: String,
    oid: Vec<u8>,
    mutable: bool,
    value: Vec<u32>
}

#[async_trait]
impl MibValue for intu32 {
    fn oid(&self) -> String {
        return self.oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned();
    }
    async fn walk(&mut self, client: &Snmp2cClient) -> Option<String> {
        match ObjectIdentifier::from_str(&self.oid()) {
            Ok(res) => {
                match client.walk_bulk(res, 100).await {
                    Ok(res) => {
                        self.value = res.into_iter().map(|a| 
                            match a.1.as_u32() {
                                Some(res) => res,
                                None => 0,
                            }
                        ).collect::<Vec<u32>>();
                        return None;
                    },
                    Err(_) => {
                        return Some("error completing snmp walk".to_owned());
                    },
                };
            }
            Err(_) => {
                return Some("error creating oid from string".to_owned());
            }
        };
    }
}

impl Clone for intu32 {
    fn clone(&self) -> Self {
        intu32 { 
            name:    self.name.clone(), 
            oid:     self.oid.to_owned(), 
            mutable: self.mutable.clone(), 
            value:   self.value.to_owned() 
        }
    }
}

struct intu64 {
    name: String,
    oid: Vec<u8>,
    mutable: bool,
    value: Vec<u64>
}

#[async_trait]
impl MibValue for intu64 {
    fn oid(&self) -> String {
        return self.oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned();
    }
    async fn walk(&mut self, client: &Snmp2cClient) -> Option<String> {
        match ObjectIdentifier::from_str(&self.oid()) {
            Ok(res) => {
                match client.walk_bulk(res, 100).await {
                    Ok(res) => {
                        self.value = res.into_iter().map(|a| 
                            match a.1.as_u64() {
                                Some(res) => res,
                                None => 0,
                            }
                        ).collect::<Vec<u64>>();
                        return None;
                    },
                    Err(_) => {
                        return Some("error completing snmp walk".to_owned());
                    },
                };
            }
            Err(_) => {
                return Some("error creating oid from string".to_owned());
            }
        };
    }
}

impl Clone for intu64 {
    fn clone(&self) -> Self {
        intu64 { 
            name:    self.name.clone(), 
            oid:     self.oid.to_owned(), 
            mutable: self.mutable.clone(), 
            value:   self.value.to_owned() 
        }
    }
}

struct oid {
    name: String,
    oid: Vec<u8>,
    mutable: bool,
    value: Vec<Vec<u8>>
}

#[async_trait]
impl MibValue for oid {
    fn oid(&self) -> String {
        return self.oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned();
    }
    async fn walk(&mut self, client: &Snmp2cClient) -> Option<String> {
        match ObjectIdentifier::from_str(&self.oid()) {
            Ok(res) => {
                match client.walk_bulk(res, 100).await {
                    Ok(res) => {
                        self.value = res.into_iter().map(|a| 
                            match a.1.as_oid() {
                                Some(res) => res.as_slice().to_vec().into_iter().map(|a| a as u8).collect::<Vec<u8>>(),
                                None => vec![],
                            }
                        ).collect::<Vec<Vec<u8>>>();
                        return None;
                    },
                    Err(_) => {
                        return Some("error completing snmp walk".to_owned());
                    },
                };
            }
            Err(_) => {
                return Some("error creating oid from string".to_owned());
            }
        };
    }
}

impl Clone for oid {
    fn clone(&self) -> Self {
        oid { 
            name:    self.name.clone(), 
            oid:     self.oid.to_owned(), 
            mutable: self.mutable.clone(), 
            value:   self.value.to_owned() 
        }
    }
}

struct ipv4 {
    name: String,
    oid: Vec<u8>,
    mutable: bool,
    value: Vec<(u8,u8,u8,u8)>
}

#[async_trait]
impl MibValue for ipv4 {
    fn oid(&self) -> String {
        return self.oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned();
    }
    async fn walk(&mut self, client: &Snmp2cClient) -> Option<String> {
        match ObjectIdentifier::from_str(&self.oid()) {
            Ok(res) => {
                match client.walk_bulk(res, 100).await {
                    Ok(res) => {
                        self.value = res.into_iter().map(|a| 
                            match a.1.as_bytes() {
                                Some(res) => {
                                    let c = match String::from_utf8(res.to_owned()) {
                                        Ok(res) => res.split(".").into_iter().map(|b| match b.parse::<u8>() {
                                                Ok(e) => e,
                                                Err(_) => 0,
                                            }).collect::<Vec<u8>>(),
                                        Err(_) => vec![0,0,0,0],
                                    };
                                    if c.len() == 4 {
                                        (c[0],c[1],c[2],c[3])
                                    } else {
                                        (0,0,0,0)
                                    }
                                },
                                None => (0,0,0,0),
                            }
                        ).collect::<Vec<(u8,u8,u8,u8)>>();
                        return None;
                    },
                    Err(_) => {
                        return Some("error completing snmp walk".to_owned());
                    },
                };
            }
            Err(_) => {
                return Some("error creating oid from string".to_owned());
            }
        };
    }
}

impl Clone for ipv4 {
    fn clone(&self) -> Self {
        ipv4 { 
            name:    self.name.clone(), 
            oid:     self.oid.to_owned(), 
            mutable: self.mutable.clone(), 
            value:   self.value.to_owned() 
        }
    }
}

struct mac {
    name: String,
    oid: Vec<u8>,
    mutable: bool,
    value: Vec<(u16,u16,u16,u16,u16,u16)>
}

#[async_trait]
impl MibValue for mac {
    fn oid(&self) -> String {
        return self.oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned();
    }
    async fn walk(&mut self, client: &Snmp2cClient) -> Option<String> {
        match ObjectIdentifier::from_str(&self.oid()) {
            Ok(res) => {
                match client.walk_bulk(res, 100).await {
                    Ok(res) => {
                        self.value = res.into_iter().map(|a| 
                            match a.1.as_bytes() {
                                Some(res) => {
                                    let c = match String::from_utf8(res.to_owned()) {
                                        Ok(res) => res.split(".").into_iter().map(|b| match b.parse::<u16>() {
                                                Ok(e) => e,
                                                Err(_) => 0,
                                            }).collect::<Vec<u16>>(),
                                        Err(_) => vec![0,0,0,0,0,0],
                                    };
                                    if c.len() == 6 {
                                        (c[0],c[1],c[2],c[3],c[4],c[5])
                                    } else {
                                        (0,0,0,0,0,0)
                                    }
                                },
                                None => (0,0,0,0,0,0),
                            }
                        ).collect::<Vec<(u16,u16,u16,u16,u16,u16)>>();
                        return None;
                    },
                    Err(_) => {
                        return Some("error completing snmp walk".to_owned());
                    },
                };
            }
            Err(_) => {
                return Some("error creating oid from string".to_owned());
            }
        };
    }
}

impl Clone for mac {
    fn clone(&self) -> Self {
        mac { 
            name:    self.name.clone(), 
            oid:     self.oid.to_owned(), 
            mutable: self.mutable.clone(), 
            value:   self.value.to_owned() 
        }
    }
}

struct ipv6 {
    name: String,
    oid: Vec<u8>,
    mutable: bool,
    value: Vec<(u16,u16,u16,u16,u16,u16,u16,u16)>
}

#[async_trait]
impl MibValue for ipv6 {
    fn oid(&self) -> String {
        return self.oid.clone().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".").to_owned();
    }
    async fn walk(&mut self, client: &Snmp2cClient) -> Option<String> {
        match ObjectIdentifier::from_str(&self.oid()) {
            Ok(res) => {
                match client.walk_bulk(res, 100).await {
                    Ok(res) => {
                        self.value = res.into_iter().map(|a| 
                            match a.1.as_bytes() {
                                Some(res) => {
                                    let c = match String::from_utf8(res.to_owned()) {
                                        Ok(res) => res.split(".").into_iter().map(|b| match b.parse::<u16>() {
                                                Ok(e) => e,
                                                Err(_) => 0,
                                            }).collect::<Vec<u16>>(),
                                        Err(_) => vec![0,0,0,0,0,0,0,0],
                                    };
                                    if c.len() == 8 {
                                        (c[0],c[1],c[2],c[3],c[4],c[5],c[6],c[7])
                                    } else {
                                        (0,0,0,0,0,0,0,0)
                                    }
                                },
                                None => (0,0,0,0,0,0,0,0),
                            }
                        ).collect::<Vec<(u16,u16,u16,u16,u16,u16,u16,u16)>>();
                        return None;
                    },
                    Err(_) => {
                        return Some("error completing snmp walk".to_owned());
                    },
                };
            }
            Err(_) => {
                return Some("error creating oid from string".to_owned());
            }
        };
    }
}

impl Clone for ipv6 {
    fn clone(&self) -> Self {
        ipv6 { 
            name:    self.name.clone(), 
            oid:     self.oid.to_owned(), 
            mutable: self.mutable.clone(), 
            value:   self.value.to_owned() 
        }
    }
}

#[tokio::main]
async fn main() {    
    println!("start");
    let (sender, reciever) = std::sync::mpsc::channel();


    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("SNMP Monitor".to_string()).with_app_id("SNMP_Monitor").with_min_inner_size([854.0,480.0]).with_maximized(true),
        ..Default::default()
    };

    let app: AppCreator = Box::new(|_| Box::new(SnmpMonitorApp { 
        name: "SNMP_Monitor".to_owned(), 
        target_ip: IpAddr::from_str("127.0.0.1").unwrap(), 
        community: "public".to_owned(), 
        reciever: reciever, 
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
        let mut interval = time::interval(Duration::from_secs(15));

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

        'monitor_loop: loop {
            println!("loop repeat");
            interval.tick().await;
            
            let mut object = MibObject::new();

            println!("sending snmp req");

            object.walk(&client).await;
            
            println!("got snmp bulk walk response");
            
            println!("{}", std::mem::size_of_val(&object));

            println!("{:?}, {:?}", &object.system.sysDesc.name, &object.system.sysDesc.value);

            sender.send(object).expect("msg");
        }
    });

    println!("run egui");

    eframe::run_native("SNMP Monitor", options, app).unwrap();
}

impl eframe::App for SnmpMonitorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        match self.reciever.try_recv() {
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
                    // ui.heading("side panel").rect.bottom();
                    ui.collapsing("System", |ui| {
                        ui.collapsing(&mibobj.system.sysDesc.name,     |ui| match &mibobj.system.sysDesc.value.len()     { 1 => ui.label(mibobj.system.sysDesc.value.first().unwrap()), _ => ui.spinner() });
                        ui.collapsing(&mibobj.system.sysObjectID.name, |ui| match &mibobj.system.sysObjectID.value.len() { 1 => ui.label(mibobj.system.sysObjectID.value.first().unwrap().into_iter().map(|a| a.to_string()).collect::<Vec<String>>().join(".")), _ => ui.spinner() });
                        ui.collapsing(&mibobj.system.sysUpTime.name,   |ui| match &mibobj.system.sysUpTime.value.len()   { 1 => ui.label(mibobj.system.sysUpTime.value.first().unwrap().to_string()), _ => ui.spinner() });
                        ui.collapsing(&mibobj.system.sysContact.name,  |ui| match &mibobj.system.sysContact.value.len()  { 1 => ui.label(mibobj.system.sysContact.value.first().unwrap()), _ => ui.spinner() });
                        ui.collapsing(&mibobj.system.sysName.name,     |ui| match &mibobj.system.sysName.value.len()     { 1 => ui.label(mibobj.system.sysName.value.first().unwrap()), _ => ui.spinner() });
                        ui.collapsing(&mibobj.system.sysLocation.name, |ui| match &mibobj.system.sysLocation.value.len() { 1 => ui.label(mibobj.system.sysLocation.value.first().unwrap()), _ => ui.spinner() });
                        ui.collapsing(&mibobj.system.sysServices.name, |ui| match &mibobj.system.sysServices.value.len() { 1 => ui.label(mibobj.system.sysServices.value.first().unwrap().to_string()), _ => ui.spinner() });
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
                });
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("center panel");
                });
            }
        }
    }
}

impl MibObject {
    fn new() -> Self {
        MibObject { 
            oid: vec![1,3,6,1,2,1], 
            system: System { 
                sysDesc: MibString     { name: "sysDesc".to_owned(),     oid: vec![1,3,6,1,2,1,1,1], mutable: false, value: vec![] }, 
                sysObjectID: oid       { name: "sysObjectID".to_owned(), oid: vec![1,3,6,1,2,1,1,2], mutable: false, value: vec![] }, 
                sysUpTime: intu32      { name: "sysUpTime".to_owned(),   oid: vec![1,3,6,1,2,1,1,3], mutable: false, value: vec![] }, 
                sysContact: MibString  { name: "sysContact".to_owned(),  oid: vec![1,3,6,1,2,1,1,4], mutable: true,  value: vec![] }, 
                sysName: MibString     { name: "sysName".to_owned(),     oid: vec![1,3,6,1,2,1,1,5], mutable: true,  value: vec![] }, 
                sysLocation: MibString { name: "sysLocation".to_owned(), oid: vec![1,3,6,1,2,1,1,6], mutable: true,  value: vec![] }, 
                sysServices: inti32    { name: "sysServices".to_owned(), oid: vec![1,3,6,1,2,1,1,7], mutable: false, value: vec![] }, 
            }, 
            interfaces: Interfaces { 
                ifNumber: inti32 { name: "ifNumber".to_owned(), oid: vec![1,3,6,1,2,1,2,1], mutable: false, value: vec![] }, 
                ifTable: IfTable { 
                    ifIndex:           inti32    { name: "ifIndex".to_owned(),           oid: vec![1,3,6,1,2,1,2,2,1,1],  mutable: false, value: vec![] }, 
                    ifDescr:           MibString { name: "ifDescr".to_owned(),           oid: vec![1,3,6,1,2,1,2,2,1,2],  mutable: false, value: vec![] }, 
                    ifType:            inti32    { name: "ifType".to_owned(),            oid: vec![1,3,6,1,2,1,2,2,1,3],  mutable: false, value: vec![] }, 
                    ifMtu:             inti32    { name: "ifMtu".to_owned(),             oid: vec![1,3,6,1,2,1,2,2,1,4],  mutable: false, value: vec![] }, 
                    ifSpeed:           intu32    { name: "ifSpeed".to_owned(),           oid: vec![1,3,6,1,2,1,2,2,1,5],  mutable: false, value: vec![] }, 
                    ifPhysAddress:     ipv6      { name: "ifPhysAddress".to_owned(),     oid: vec![1,3,6,1,2,1,2,2,1,6],  mutable: false, value: vec![] }, 
                    ifAdminStatus:     inti32    { name: "ifAdminStatus".to_owned(),     oid: vec![1,3,6,1,2,1,2,2,1,7],  mutable: true,  value: vec![] }, 
                    ifOperStatus:      inti32    { name: "ifOperStatus".to_owned(),      oid: vec![1,3,6,1,2,1,2,2,1,8],  mutable: false, value: vec![] }, 
                    ifLastChange:      intu32    { name: "ifLastChange".to_owned(),      oid: vec![1,3,6,1,2,1,2,2,1,9],  mutable: false, value: vec![] }, 
                    ifInOctets:        intu32    { name: "ifInOctets".to_owned(),        oid: vec![1,3,6,1,2,1,2,2,1,10], mutable: false, value: vec![] }, 
                    ifInUcastPkts:     intu32    { name: "ifInUcastPkts".to_owned(),     oid: vec![1,3,6,1,2,1,2,2,1,11], mutable: false, value: vec![] }, 
                    ifInNUcastPkts:    intu32    { name: "ifInNUcastPkts".to_owned(),    oid: vec![1,3,6,1,2,1,2,2,1,12], mutable: false, value: vec![] }, 
                    ifInDiscards:      intu32    { name: "ifInDiscards".to_owned(),      oid: vec![1,3,6,1,2,1,2,2,1,13], mutable: false, value: vec![] }, 
                    ifInErrors:        intu32    { name: "ifInErrors".to_owned(),        oid: vec![1,3,6,1,2,1,2,2,1,14], mutable: false, value: vec![] }, 
                    ifInUnknownProtos: intu32    { name: "ifInUnknownProtos".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,15], mutable: false, value: vec![] }, 
                    ifOutOctets:       intu32    { name: "ifOutOctets".to_owned(),       oid: vec![1,3,6,1,2,1,2,2,1,16], mutable: false, value: vec![] }, 
                    ifOutUcastPkts:    intu32    { name: "ifOutUcastPkts".to_owned(),    oid: vec![1,3,6,1,2,1,2,2,1,17], mutable: false, value: vec![] }, 
                    ifOutNUcastPkts:   intu32    { name: "ifOutNUcastPkts".to_owned(),   oid: vec![1,3,6,1,2,1,2,2,1,18], mutable: false, value: vec![] }, 
                    ifOutDiscards:     intu32    { name: "ifOutDiscards".to_owned(),     oid: vec![1,3,6,1,2,1,2,2,1,19], mutable: false, value: vec![] }, 
                    ifOutErrors:       intu32    { name: "ifOutErrors".to_owned(),       oid: vec![1,3,6,1,2,1,2,2,1,20], mutable: false, value: vec![] }, 
                    ifOutQLen:         intu32    { name: "ifOutQLen".to_owned(),         oid: vec![1,3,6,1,2,1,2,2,1,21], mutable: false, value: vec![] }, 
                    ifSpecific:        oid       { name: "ifSpecific".to_owned(),        oid: vec![1,3,6,1,2,1,2,2,1,22], mutable: false, value: vec![] }, 
                } 
            }, 
            at: At { 
                atTable: AtTable { 
                    atIfIndex:     inti32    { name: "atIfIndex".to_owned(),     oid: vec![1,3,6,1,2,1,3,1,1,1], mutable: true, value: vec![] }, 
                    atPhysAddress: ipv6      { name: "atPhysAddress".to_owned(), oid: vec![1,3,6,1,2,1,3,1,1,2], mutable: true, value: vec![] }, 
                    atNetAddress:  MibString { name: "atNetAddress".to_owned(),  oid: vec![1,3,6,1,2,1,3,1,1,3], mutable: true, value: vec![] }, 
                }
            }, 
            ip: Ip { 
                ipForwarding:      inti32 { name: "ipForwarding".to_owned(),      oid: vec![1,2,6,1,2,1,4,1],  mutable: true,  value: vec![] }, 
                ipDefaultTTL:      inti32 { name: "ipDefaultTTL".to_owned(),      oid: vec![1,2,6,1,2,1,4,2],  mutable: true,  value: vec![] }, 
                ipInReceives:      intu32 { name: "ipInReceives".to_owned(),      oid: vec![1,2,6,1,2,1,4,3],  mutable: false, value: vec![] }, 
                ipInHdrErrors:     intu32 { name: "ipInHdrErrors".to_owned(),     oid: vec![1,2,6,1,2,1,4,4],  mutable: false, value: vec![] }, 
                ipInAddrErrors:    intu32 { name: "ipInAddrErrors".to_owned(),    oid: vec![1,2,6,1,2,1,4,5],  mutable: false, value: vec![] }, 
                ipForwDatagrams:   intu32 { name: "ipForwDatagrams".to_owned(),   oid: vec![1,2,6,1,2,1,4,6],  mutable: false, value: vec![] }, 
                ipInUnknownProtos: intu32 { name: "ipInUnknownProtos".to_owned(), oid: vec![1,2,6,1,2,1,4,7],  mutable: false, value: vec![] }, 
                ipInDiscards:      intu32 { name: "ipInDiscards".to_owned(),      oid: vec![1,2,6,1,2,1,4,8],  mutable: false, value: vec![] }, 
                ipInDelivers:      intu32 { name: "ipInDelivers".to_owned(),      oid: vec![1,2,6,1,2,1,4,9],  mutable: false, value: vec![] }, 
                ipOutRequests:     intu32 { name: "ipOutRequests".to_owned(),     oid: vec![1,2,6,1,2,1,4,10], mutable: false, value: vec![] }, 
                ipOutDiscards:     intu32 { name: "ipOutDiscards".to_owned(),     oid: vec![1,2,6,1,2,1,4,11], mutable: false, value: vec![] }, 
                ipOutNoRoutes:     intu32 { name: "ipOutNoRoutes".to_owned(),     oid: vec![1,2,6,1,2,1,4,12], mutable: false, value: vec![] }, 
                ipReasmTimeout:    inti32 { name: "ipReasmTimeout".to_owned(),    oid: vec![1,2,6,1,2,1,4,13], mutable: false, value: vec![] }, 
                ipReasmReqds:      intu32 { name: "ipReasmReqds".to_owned(),      oid: vec![1,2,6,1,2,1,4,14], mutable: false, value: vec![] }, 
                ipReasmOKs:        intu32 { name: "ipReasmOKs".to_owned(),        oid: vec![1,2,6,1,2,1,4,15], mutable: false, value: vec![] }, 
                ipReasmFails:      intu32 { name: "ipReasmFails".to_owned(),      oid: vec![1,2,6,1,2,1,4,16], mutable: false, value: vec![] }, 
                ipFragOKs:         intu32 { name: "ipFragOKs".to_owned(),         oid: vec![1,2,6,1,2,1,4,17], mutable: false, value: vec![] }, 
                ipFragFails:       intu32 { name: "ipFragFails".to_owned(),       oid: vec![1,2,6,1,2,1,4,18], mutable: false, value: vec![] }, 
                ipFragCreates:     intu32 { name: "ipFragCreates".to_owned(),     oid: vec![1,2,6,1,2,1,4,19], mutable: false, value: vec![] }, 
                ipAddrTable: IpAddrTable { 
                    ipAdEntAddr:         MibString  { name: "ipAdEntAddr".to_owned(),         oid: vec![], mutable: false, value: vec![] }, 
                    ipAdEntIfIndex:      inti32     { name: "ipAdEntIfIndex".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                    ipAdEntNetMask:      MibString  { name: "ipAdEntNetMask".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                    ipAdEntBcastAddr:    inti32     { name: "ipAdEntBcastAddr".to_owned(),    oid: vec![], mutable: false, value: vec![] }, 
                    ipAdEntReasmMaxSize: inti32     { name: "ipAdEntReasmMaxSize".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
                }, 
                ipRouteTable: IpRouteTable { 
                    ipRouteDest:    MibString   { name: "ipRouteDest".to_owned(),    oid: vec![], mutable: true, value: vec![] }, 
                    ipRouteIfIndex: inti32      { name: "ipRouteIfIndex".to_owned(), oid: vec![], mutable: true, value: vec![] }, 
                    ipRouteMetric1: inti32      { name: "ipRouteMetric1".to_owned(), oid: vec![], mutable: true, value: vec![] }, 
                    ipRouteMetric2: inti32      { name: "ipRouteMetric2".to_owned(), oid: vec![], mutable: true, value: vec![] }, 
                    ipRouteMetric3: inti32      { name: "ipRouteMetric3".to_owned(), oid: vec![], mutable: true, value: vec![] }, 
                    ipRouteMetric4: inti32      { name: "ipRouteMetric4".to_owned(), oid: vec![], mutable: true, value: vec![] }, 
                    ipRouteNextHop: MibString   { name: "ipRouteNextHop".to_owned(), oid: vec![], mutable: true, value: vec![] }, 
                    ipRouteType:    inti32      { name: "ipRouteType".to_owned(),    oid: vec![], mutable: true, value: vec![] }, 
                    ipRouteProto:   inti32      { name: "ipRouteProto".to_owned(),   oid: vec![], mutable: true, value: vec![] }, 
                    ipRouteAge:     inti32      { name: "ipRouteAge".to_owned(),     oid: vec![], mutable: true, value: vec![] }, 
                    ipRouteMask:    MibString   { name: "ipRouteMask".to_owned(),    oid: vec![], mutable: true, value: vec![] }, 
                    ipRouteMetric5: inti32      { name: "ipRouteMetric5".to_owned(), oid: vec![], mutable: true, value: vec![] }, 
                    ipRouteInfo:    oid         { name: "ipRouteInfo".to_owned(),    oid: vec![], mutable: true, value: vec![] }, 
                }, 
                ipNetToMediaTable: IpNetToMediaTable { 
                    ipNetToMediaIfIndex:     inti32     { name: "ipNetToMediaIfIndex".to_owned(),     oid: vec![], mutable: true, value: vec![] }, 
                    ipNetToMediaPhysAddress: ipv6       { name: "ipNetToMediaPhysAddress".to_owned(), oid: vec![], mutable: true, value: vec![] }, 
                    ipNetToMediaNetAddress:  MibString  { name: "ipNetToMediaNetAddress".to_owned(),  oid: vec![], mutable: true, value: vec![] }, 
                    ipNetToMediaType:        inti32     { name: "ipNetToMediaType".to_owned(),        oid: vec![], mutable: true, value: vec![] }, 
                }, 
                ipRoutingDiscards: inti32 { name: "ipRoutingDiscards".to_owned(), oid: vec![], mutable: false, value: vec![] }
            }, 
            icmp: Icmp { 
                icmpInMsgs:           inti32 { name: "icmpInMsgs".to_owned(),           oid: vec![], mutable: false, value: vec![] }, 
                icmpInErrors:         inti32 { name: "icmpInErrors".to_owned(),         oid: vec![], mutable: false, value: vec![] }, 
                icmpInDestUnreachs:   inti32 { name: "icmpInDestUnreachs".to_owned(),   oid: vec![], mutable: false, value: vec![] }, 
                icmpInTimeExcds:      inti32 { name: "icmpInTimeExcds".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                icmpInParmProbs:      inti32 { name: "icmpInParmProbs".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                icmpInSrcQuenchs:     inti32 { name: "icmpInSrcQuenchs".to_owned(),     oid: vec![], mutable: false, value: vec![] }, 
                icmpInRedirects:      inti32 { name: "icmpInRedirects".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                icmpInEchos:          inti32 { name: "icmpInEchos".to_owned(),          oid: vec![], mutable: false, value: vec![] }, 
                icmpInEchoReps:       inti32 { name: "icmpInEchoReps".to_owned(),       oid: vec![], mutable: false, value: vec![] }, 
                icmpInTimestamps:     inti32 { name: "icmpInTimestamps".to_owned(),     oid: vec![], mutable: false, value: vec![] }, 
                icmpInTimestampReps:  inti32 { name: "icmpInTimestampReps".to_owned(),  oid: vec![], mutable: false, value: vec![] }, 
                icmpInAddrMasks:      inti32 { name: "icmpInAddrMasks".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                icmpInAddrMaskReps:   inti32 { name: "icmpInAddrMaskReps".to_owned(),   oid: vec![], mutable: false, value: vec![] }, 
                icmpOutMsgs:          inti32 { name: "icmpOutMsgs".to_owned(),          oid: vec![], mutable: false, value: vec![] }, 
                icmpOutErrors:        inti32 { name: "icmpOutErrors".to_owned(),        oid: vec![], mutable: false, value: vec![] }, 
                icmpOutDestUnreachs:  inti32 { name: "icmpOutDestUnreachs".to_owned(),  oid: vec![], mutable: false, value: vec![] }, 
                icmpOutTimeExcds:     inti32 { name: "icmpOutTimeExcds".to_owned(),     oid: vec![], mutable: false, value: vec![] }, 
                icmpOutParmProbs:     inti32 { name: "icmpOutParmProbs".to_owned(),     oid: vec![], mutable: false, value: vec![] }, 
                icmpOutSrcQuenchs:    inti32 { name: "icmpOutSrcQuenchs".to_owned(),    oid: vec![], mutable: false, value: vec![] }, 
                icmpOutRedirects:     inti32 { name: "icmpOutRedirects".to_owned(),     oid: vec![], mutable: false, value: vec![] }, 
                icmpOutEchos:         inti32 { name: "icmpOutEchos".to_owned(),         oid: vec![], mutable: false, value: vec![] }, 
                icmpOutEchoReps:      inti32 { name: "icmpOutEchoReps".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                icmpOutTimestamps:    inti32 { name: "icmpOutTimestamps".to_owned(),    oid: vec![], mutable: false, value: vec![] }, 
                icmpOutTimestampReps: inti32 { name: "icmpOutTimestampReps".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
                icmpOutAddrMasks:     inti32 { name: "icmpOutAddrMasks".to_owned(),     oid: vec![], mutable: false, value: vec![] }, 
                icmpOutAddrMaskReps:  inti32 { name: "icmpOutAddrMaskReps".to_owned(),  oid: vec![], mutable: false, value: vec![] }, 
            }, 
            tcp: Tcp { 
                tcpRtoAlgorithm: inti32 { name: "tcpRtoAlgorithm".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
                tcpRtoMin:       inti32 { name: "tcpRtoMin".to_owned(),       oid: vec![], mutable: false, value: vec![] }, 
                tcpRtoMax:       inti32 { name: "tcpRtoMax".to_owned(),       oid: vec![], mutable: false, value: vec![] }, 
                tcpMaxConn:      inti32 { name: "tcpMaxConn".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                tcpActiveOpens:  intu32 { name: "tcpActiveOpens".to_owned(),  oid: vec![], mutable: false, value: vec![] }, 
                tcpPassiveOpens: intu32 { name: "tcpPassiveOpens".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
                tcpAttemptFails: intu32 { name: "tcpAttemptFails".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
                tcpEstabResets:  intu32 { name: "tcpEstabResets".to_owned(),  oid: vec![], mutable: false, value: vec![] }, 
                tcpCurrEstab:    intu32 { name: "tcpCurrEstab".to_owned(),    oid: vec![], mutable: false, value: vec![] }, 
                tcpInSegs:       intu32 { name: "tcpInSegs".to_owned(),       oid: vec![], mutable: false, value: vec![] }, 
                tcpOutSegs:      intu32 { name: "tcpOutSegs".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                tcpRetransSegs:  intu32 { name: "tcpRetransSegs".to_owned(),  oid: vec![], mutable: false, value: vec![] }, 
                tcpConnTable: TcpConnTable { 
                    tcpConnState:        inti32     { name: "tcpConnState".to_owned(),        oid: vec![], mutable: true,  value: vec![] }, 
                    tcpConnLocalAddress: MibString  { name: "tcpConnLocalAddress".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
                    tcpConnLocalPort:    inti32     { name: "tcpConnLocalPort".to_owned(),    oid: vec![], mutable: false, value: vec![] }, 
                    tcpConnRemAddress:   MibString  { name: "tcpConnRemAddress".to_owned(),   oid: vec![], mutable: false, value: vec![] }, 
                    tcpConnRemPort:      inti32     { name: "tcpConnRemPort".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                }, 
                tcpInErrs: intu32  { name: "tcpInErrs".to_owned(),  oid: vec![], mutable: false, value: vec![] }, 
                tcpOutRsts: intu32 { name: "tcpOutRsts".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
            }, 
            udp: Udp { 
                udpInDatagrams:  intu32 { name: "udpInDatagrams".to_owned(),  oid: vec![], mutable: false, value: vec![] }, 
                udpNoPorts:      intu32 { name: "udpNoPorts".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                udpInErrors:     intu32 { name: "udpInErrors".to_owned(),     oid: vec![], mutable: false, value: vec![] }, 
                udpOutDatagrams: intu32 { name: "udpOutDatagrams".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
                udpTable: UdpTable { 
                    udpLocalAddress: MibString  { name: "udpLocalAddress".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
                    udpLocalPort:    inti32     { name: "udpLocalPort".to_owned(),    oid: vec![], mutable: false, value: vec![] }, 
                } 
            }, 
            egp: Egp { 
                egpInMsgs:    intu32 { name: "egpInMsgs".to_owned(),    oid: vec![], mutable: false, value: vec![] }, 
                egpInErrors:  intu32 { name: "egpInErrors".to_owned(),  oid: vec![], mutable: false, value: vec![] }, 
                egpOutMsgs:   intu32 { name: "egpOutMsgs".to_owned(),   oid: vec![], mutable: false, value: vec![] }, 
                egpOutErrors: intu32 { name: "egpOutErrors".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
                egpNeighTable: EgpNeighTable { 
                    egpNeighState:         inti32       { name: "egpNeighState".to_owned(),         oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighAddr:          MibString    { name: "egpNeighAddr".to_owned(),          oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighAs:            inti32       { name: "egpNeighAs".to_owned(),            oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighInMsgs:        intu32       { name: "egpNeighInMsgs".to_owned(),        oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighInErrs:        intu32       { name: "egpNeighInErrs".to_owned(),        oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighOutMsgs:       intu32       { name: "egpNeighOutMsgs".to_owned(),       oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighOutErrs:       intu32       { name: "egpNeighOutErrs".to_owned(),       oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighInErrMsgs:     intu32       { name: "egpNeighInErrMsgs".to_owned(),     oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighOutErrMsgs:    intu32       { name: "egpNeighOutErrMsgs".to_owned(),    oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighStateUps:      intu32       { name: "egpNeighStateUps".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighStateDowns:    intu32       { name: "egpNeighStateDowns".to_owned(),    oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighIntervalHello: inti32       { name: "egpNeighIntervalHello".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighIntervalPoll:  inti32       { name: "egpNeighIntervalPoll".to_owned(),  oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighMode:          inti32       { name: "egpNeighMode".to_owned(),          oid: vec![], mutable: false, value: vec![] }, 
                    egpNeighEventTrigger:  inti32       { name: "egpNeighEventTrigger".to_owned(),  oid: vec![], mutable: true,  value: vec![] }, 
                }, 
                egpAs: inti32 { name: "egpAs".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
            }, 
            transmission: MibString { name: "transmission".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
            snmp: Snmp { 
                snmpInPkts:              intu32 { name: "snmpInPkts".to_owned(),              oid: vec![], mutable: false, value: vec![] }, 
                snmpOutPkts:             intu32 { name: "snmpOutPkts".to_owned(),             oid: vec![], mutable: false, value: vec![] }, 
                snmpInBadVersions:       intu32 { name: "snmpInBadVersions".to_owned(),       oid: vec![], mutable: false, value: vec![] }, 
                snmpInBadCommunityNames: intu32 { name: "snmpInBadCommunityNames".to_owned(), oid: vec![], mutable: false, value: vec![] }, 
                snmpInBadCommunityUses:  intu32 { name: "snmpInBadCommunityUses".to_owned(),  oid: vec![], mutable: false, value: vec![] }, 
                snmpInASNParseErrs:      intu32 { name: "snmpInASNParseErrs".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                snmpInTooBigs:           intu32 { name: "snmpInTooBigs".to_owned(),           oid: vec![], mutable: false, value: vec![] }, 
                snmpInNoSuchNames:       intu32 { name: "snmpInNoSuchNames".to_owned(),       oid: vec![], mutable: false, value: vec![] }, 
                snmpInBadValues:         intu32 { name: "snmpInBadValues".to_owned(),         oid: vec![], mutable: false, value: vec![] }, 
                snmpInReadOnlys:         intu32 { name: "snmpInReadOnlys".to_owned(),         oid: vec![], mutable: false, value: vec![] }, 
                snmpInGenErrs:           intu32 { name: "snmpInGenErrs".to_owned(),           oid: vec![], mutable: false, value: vec![] }, 
                snmpInTotalReqVars:      intu32 { name: "snmpInTotalReqVars".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                snmpInTotalSetVars:      intu32 { name: "snmpInTotalSetVars".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                snmpInGetRequests:       intu32 { name: "snmpInGetRequests".to_owned(),       oid: vec![], mutable: false, value: vec![] }, 
                snmpInGetNexts:          intu32 { name: "snmpInGetNexts".to_owned(),          oid: vec![], mutable: false, value: vec![] }, 
                snmpInSetRequests:       intu32 { name: "snmpInSetRequests".to_owned(),       oid: vec![], mutable: false, value: vec![] }, 
                snmpInGetResponses:      intu32 { name: "snmpInGetResponses".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                snmpInTraps:             intu32 { name: "snmpInTraps".to_owned(),             oid: vec![], mutable: false, value: vec![] }, 
                snmpOutTooBigs:          intu32 { name: "snmpOutTooBigs".to_owned(),          oid: vec![], mutable: false, value: vec![] }, 
                snmpOutNoSuchNames:      intu32 { name: "snmpOutNoSuchNames".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                snmpOutBadValues:        intu32 { name: "snmpOutBadValues".to_owned(),        oid: vec![], mutable: false, value: vec![] }, 
                snmpOutGenErrs:          intu32 { name: "snmpOutGenErrs".to_owned(),          oid: vec![], mutable: false, value: vec![] }, 
                snmpOutGetRequests:      intu32 { name: "snmpOutGetRequests".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                snmpOutGetNexts:         intu32 { name: "snmpOutGetNexts".to_owned(),         oid: vec![], mutable: false, value: vec![] }, 
                snmpOutSetRequests:      intu32 { name: "snmpOutSetRequests".to_owned(),      oid: vec![], mutable: false, value: vec![] }, 
                snmpOutGetResponses:     intu32 { name: "snmpOutGetResponses".to_owned(),     oid: vec![], mutable: false, value: vec![] }, 
                snmpOutTraps:            intu32 { name: "snmpOutTraps".to_owned(),            oid: vec![], mutable: false, value: vec![] }, 
                snmpEnableAuthenTraps:   inti32 { name: "snmpEnableAuthenTraps".to_owned(),   oid: vec![], mutable: true,  value: vec![] } 
            } 
        }
    }
}