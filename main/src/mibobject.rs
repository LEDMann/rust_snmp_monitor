pub mod MibModule {
    use std::{str::FromStr, net::Ipv4Addr};
    use async_trait::async_trait;
    use csnmp::{Snmp2cClient, ObjectIdentifier};
    use serde::{Deserialize, Serialize};
    
    #[derive(Serialize, Deserialize)]
    pub struct MibObject { 
        pub oid: Vec<u16>, 
        pub system: System, 
        pub interfaces: Interfaces, 
        pub at: At, 
        pub ip: Ip, 
        pub icmp: Icmp, 
        pub tcp: Tcp, 
        pub udp: Udp, 
        pub egp: Egp, 
        pub transmission: oid, 
        pub snmp: Snmp, 
    }
    
    #[derive(Serialize, Deserialize)]
    pub struct System { 
        pub sysDesc: MibString, 
        pub sysObjectID: oid, 
        pub sysUpTime: intu32, 
        pub sysContact: MibString, 
        pub sysName: MibString, 
        pub sysLocation: MibString, 
        pub sysServices: inti32, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct Interfaces { 
        pub ifNumber: inti32, 
        pub ifTable: IfTable, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct IfTable { 
        pub ifIndex: inti32, 
        pub ifDescr: MibString, 
        pub ifType: inti32, 
        pub ifMtu: inti32, 
        pub ifSpeed: intu32, 
        pub ifPhysAddress: ipv6, 
        pub ifAdminStatus: inti32, 
        pub ifOperStatus: inti32, 
        pub ifLastChange: intu32, 
        pub ifInOctets: intu32, 
        pub ifInUcastPkts: intu32, 
        pub ifInNUcastPkts: intu32, 
        pub ifInDiscards: intu32, 
        pub ifInErrors: intu32, 
        pub ifInUnknownProtos: intu32, 
        pub ifOutOctets: intu32, 
        pub ifOutUcastPkts: intu32, 
        pub ifOutNUcastPkts: intu32, 
        pub ifOutDiscards: intu32, 
        pub ifOutErrors: intu32, 
        pub ifOutQLen: intu32, 
        pub ifSpecific: oid, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct At { 
        pub atTable: AtTable, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct AtTable { 
        pub atIfIndex:     inti32, 
        pub atPhysAddress: ipv6, 
        pub atNetAddress:  ipv4, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct Ip { 
        pub ipForwarding:      inti32, 
        pub ipDefaultTTL:      inti32, 
        pub ipInReceives:      intu32, 
        pub ipInHdrErrors:     intu32, 
        pub ipInAddrErrors:    intu32, 
        pub ipForwDatagrams:   intu32, 
        pub ipInUnknownProtos: intu32, 
        pub ipInDiscards:      intu32, 
        pub ipInDelivers:      intu32, 
        pub ipOutRequests:     intu32, 
        pub ipOutDiscards:     intu32, 
        pub ipOutNoRoutes:     intu32, 
        pub ipReasmTimeout:    inti32, 
        pub ipReasmReqds:      intu32, 
        pub ipReasmOKs:        intu32, 
        pub ipReasmFails:      intu32, 
        pub ipFragOKs:         intu32, 
        pub ipFragFails:       intu32, 
        pub ipFragCreates:     intu32, 
        pub ipAddrTable:       IpAddrTable, 
        pub ipRouteTable:      IpRouteTable, 
        pub ipNetToMediaTable: IpNetToMediaTable, 
        pub ipRoutingDiscards: intu32, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct IpAddrTable { 
        pub ipAdEntAddr:         ipv4  , 
        pub ipAdEntIfIndex:      inti32, 
        pub ipAdEntNetMask:      ipv4  , 
        pub ipAdEntBcastAddr:    inti32, 
        pub ipAdEntReasmMaxSize: inti32, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct IpRouteTable { 
        pub ipRouteDest:    ipv4  , 
        pub ipRouteIfIndex: inti32, 
        pub ipRouteMetric1: inti32, 
        pub ipRouteMetric2: inti32, 
        pub ipRouteMetric3: inti32, 
        pub ipRouteMetric4: inti32, 
        pub ipRouteNextHop: ipv4  , 
        pub ipRouteType:    inti32, 
        pub ipRouteProto:   inti32, 
        pub ipRouteAge:     inti32, 
        pub ipRouteMask:    ipv4  , 
        pub ipRouteMetric5: inti32, 
        pub ipRouteInfo:    oid   , 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct IpNetToMediaTable { 
        pub ipNetToMediaIfIndex:     inti32, 
        pub ipNetToMediaPhysAddress: ipv6   , 
        pub ipNetToMediaNetAddress:  ipv4  , 
        pub ipNetToMediaType:        inti32, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct Icmp { 
        pub icmpInMsgs:           intu32, 
        pub icmpInErrors:         intu32, 
        pub icmpInDestUnreachs:   intu32, 
        pub icmpInTimeExcds:      intu32, 
        pub icmpInParmProbs:      intu32, 
        pub icmpInSrcQuenchs:     intu32, 
        pub icmpInRedirects:      intu32, 
        pub icmpInEchos:          intu32, 
        pub icmpInEchoReps:       intu32, 
        pub icmpInTimestamps:     intu32, 
        pub icmpInTimestampReps:  intu32, 
        pub icmpInAddrMasks:      intu32, 
        pub icmpInAddrMaskReps:   intu32, 
        pub icmpOutMsgs:          intu32, 
        pub icmpOutErrors:        intu32, 
        pub icmpOutDestUnreachs:  intu32, 
        pub icmpOutTimeExcds:     intu32, 
        pub icmpOutParmProbs:     intu32, 
        pub icmpOutSrcQuenchs:    intu32, 
        pub icmpOutRedirects:     intu32, 
        pub icmpOutEchos:         intu32, 
        pub icmpOutEchoReps:      intu32, 
        pub icmpOutTimestamps:    intu32, 
        pub icmpOutTimestampReps: intu32, 
        pub icmpOutAddrMasks:     intu32, 
        pub icmpOutAddrMaskReps:  intu32, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct Tcp { 
        pub tcpRtoAlgorithm: inti32, 
        pub tcpRtoMin:       inti32, 
        pub tcpRtoMax:       inti32, 
        pub tcpMaxConn:      inti32, 
        pub tcpActiveOpens:  intu32, 
        pub tcpPassiveOpens: intu32, 
        pub tcpAttemptFails: intu32, 
        pub tcpEstabResets:  intu32, 
        pub tcpCurrEstab:    intu32, 
        pub tcpInSegs:       intu32, 
        pub tcpOutSegs:      intu32, 
        pub tcpRetransSegs:  intu32, 
        pub tcpConnTable:    TcpConnTable, 
        pub tcpInErrs:       intu32, 
        pub tcpOutRsts:      intu32, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct TcpConnTable { 
        pub tcpConnState:        inti32, 
        pub tcpConnLocalAddress: ipv4  , 
        pub tcpConnLocalPort:    inti32, 
        pub tcpConnRemAddress:   ipv4  , 
        pub tcpConnRemPort:      inti32, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct Udp { 
        pub udpInDatagrams:  intu32, 
        pub udpNoPorts:      intu32, 
        pub udpInErrors:     intu32, 
        pub udpOutDatagrams: intu32, 
        pub udpTable:        UdpTable, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct UdpTable { 
        pub udpLocalAddress: ipv4  , 
        pub udpLocalPort:    inti32, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct Egp { 
        pub egpInMsgs:     intu32, 
        pub egpInErrors:   intu32, 
        pub egpOutMsgs:    intu32, 
        pub egpOutErrors:  intu32, 
        pub egpNeighTable: EgpNeighTable, 
        pub egpAs:         inti32, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct EgpNeighTable { 
        pub egpNeighState:         inti32, 
        pub egpNeighAddr:          ipv4  , 
        pub egpNeighAs:            inti32, 
        pub egpNeighInMsgs:        intu32, 
        pub egpNeighInErrs:        intu32, 
        pub egpNeighOutMsgs:       intu32, 
        pub egpNeighOutErrs:       intu32, 
        pub egpNeighInErrMsgs:     intu32, 
        pub egpNeighOutErrMsgs:    intu32, 
        pub egpNeighStateUps:      intu32, 
        pub egpNeighStateDowns:    intu32, 
        pub egpNeighIntervalHello: inti32, 
        pub egpNeighIntervalPoll:  inti32, 
        pub egpNeighMode:          inti32, 
        pub egpNeighEventTrigger:  inti32, 
    }
        
    #[derive(Serialize, Deserialize)]
    pub struct Snmp { 
        pub snmpInPkts:              intu32, 
        pub snmpOutPkts:             intu32, 
        pub snmpInBadVersions:       intu32, 
        pub snmpInBadCommunityNames: intu32, 
        pub snmpInBadCommunityUses:  intu32, 
        pub snmpInASNParseErrs:      intu32, 
        pub snmpInTooBigs:           intu32, 
        pub snmpInNoSuchNames:       intu32, 
        pub snmpInBadValues:         intu32, 
        pub snmpInReadOnlys:         intu32, 
        pub snmpInGenErrs:           intu32, 
        pub snmpInTotalReqVars:      intu32, 
        pub snmpInTotalSetVars:      intu32, 
        pub snmpInGetRequests:       intu32, 
        pub snmpInGetNexts:          intu32, 
        pub snmpInSetRequests:       intu32, 
        pub snmpInGetResponses:      intu32, 
        pub snmpInTraps:             intu32, 
        pub snmpOutTooBigs:          intu32, 
        pub snmpOutNoSuchNames:      intu32, 
        pub snmpOutBadValues:        intu32, 
        pub snmpOutGenErrs:          intu32, 
        pub snmpOutGetRequests:      intu32, 
        pub snmpOutGetNexts:         intu32, 
        pub snmpOutSetRequests:      intu32, 
        pub snmpOutGetResponses:     intu32, 
        pub snmpOutTraps:            intu32, 
        pub snmpEnableAuthenTraps:   inti32, 
    } 


    impl MibObject {
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
    }
    
    impl System {
        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.sysDesc.walk(client).await;
            self.sysObjectID.walk(client).await;
            self.sysUpTime.walk(client).await;
            self.sysContact.walk(client).await;
            self.sysName.walk(client).await;
            self.sysLocation.walk(client).await;
            self.sysServices.walk(client).await;
        }
    }
    
    impl Interfaces {
        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.ifNumber.walk(client).await;
            self.ifTable.walk(client).await;
        }
    }
    
    impl IfTable {
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
    }
    
    impl At {
        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.atTable.walk(client).await;
        }
    }
    
    impl AtTable {
        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.atIfIndex.walk(client).await;
            self.atPhysAddress.walk(client).await;
            self.atNetAddress.walk(client).await;
        }
    }
    
    impl Ip {
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
    }
    
    impl IpAddrTable {
        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.ipAdEntAddr.walk(client).await;
            self.ipAdEntIfIndex.walk(client).await;
            self.ipAdEntNetMask.walk(client).await;
            self.ipAdEntBcastAddr.walk(client).await;
            self.ipAdEntReasmMaxSize.walk(client).await;
        }
    }
    
    impl IpRouteTable {
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
    }
    
    impl IpNetToMediaTable {
        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.ipNetToMediaIfIndex.walk(client).await;
            self.ipNetToMediaPhysAddress.walk(client).await;
            self.ipNetToMediaNetAddress.walk(client).await;
            self.ipNetToMediaType.walk(client).await;
        }
    }
    
    impl Icmp {
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
    }
    
    impl Tcp {
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
    }
    
    impl TcpConnTable {
        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.tcpConnState.walk(client).await;
            self.tcpConnLocalAddress.walk(client).await;
            self.tcpConnLocalPort.walk(client).await;
            self.tcpConnRemAddress.walk(client).await;
            self.tcpConnRemPort.walk(client).await;
        }
    }
    
    impl Udp {
        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.udpInDatagrams.walk(client).await;
            self.udpNoPorts.walk(client).await;
            self.udpInErrors.walk(client).await;
            self.udpOutDatagrams.walk(client).await;
            self.udpTable.walk(client).await;
        }
    }
    
    impl UdpTable {
        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.udpLocalAddress.walk(client).await;
            self.udpLocalPort.walk(client).await;
        }
    }
    
    impl Egp {
        pub async fn walk(&mut self, client: &Snmp2cClient) {
            self.egpInMsgs.walk(client).await;
            self.egpInErrors.walk(client).await;
            self.egpOutMsgs.walk(client).await;
            self.egpOutErrors.walk(client).await;
            self.egpNeighTable.walk(client).await;
            self.egpAs.walk(client).await;
        }
    }
    
    impl EgpNeighTable {
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
    }
    
    impl Snmp {
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
    
    impl Clone for Interfaces {
        fn clone(&self) -> Self {
            Interfaces {
                ifNumber: self.ifNumber.clone(), 
                ifTable: self.ifTable.clone(), 
            }
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
    
    impl Clone for At {
        fn clone(&self) -> Self {
            At {
                atTable: self.atTable.clone(), 
            }
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
    
    impl Clone for UdpTable {
        fn clone(&self) -> Self {
            UdpTable {
                udpLocalAddress: self.udpLocalAddress.clone(), 
                udpLocalPort: self.udpLocalPort.clone(), 
            }
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
    
    impl MibObject {
        pub fn new() -> Self {
            MibObject { 
                oid: vec![1,3,6,1,2,1], 
                system: System { 
                    sysDesc: MibString     { name: "sysDesc".to_owned(), oid: vec![1,3,6,1,2,1,1,1], mutable: false, value: vec![] }, // DisplayString
                    sysObjectID: oid       { name: "sysObjectID".to_owned(), oid: vec![1,3,6,1,2,1,1,2], mutable: false, value: vec![] }, // OBJECT_IDENTIFIER
                    sysUpTime: intu32      { name: "sysUpTime".to_owned(), oid: vec![1,3,6,1,2,1,1,3], mutable: false, value: vec![] }, // TimeTicks
                    sysContact: MibString  { name: "sysContact".to_owned(), oid: vec![1,3,6,1,2,1,1,4], mutable: true, value: vec![] }, // DisplayString
                    sysName: MibString     { name: "sysName".to_owned(), oid: vec![1,3,6,1,2,1,1,5], mutable: true, value: vec![] }, // DisplayString
                    sysLocation: MibString { name: "sysLocation".to_owned(), oid: vec![1,3,6,1,2,1,1,6], mutable: true, value: vec![] }, // DisplayString
                    sysServices: inti32    { name: "sysServices".to_owned(), oid: vec![1,3,6,1,2,1,1,7], mutable: false, value: vec![] }, // INTEGER
                }, 
                interfaces: Interfaces {
                    ifNumber: inti32 { name: "ifNumber".to_owned(), oid: vec![1,3,6,1,2,1,2,1], mutable: false, value: vec![] }, // INTEGER
                    ifTable: IfTable {
                        ifIndex:           inti32    { name: "ifIndex".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,1], mutable: false, value: vec![] }, // INTEGER
                        ifDescr:           MibString { name: "ifDescr".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,2], mutable: false, value: vec![] }, // DisplayString
                        ifType:            inti32    { name: "ifType".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,3], mutable: false, value: vec![] }, // INTEGER
                        ifMtu:             inti32    { name: "ifMtu".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,4], mutable: false, value: vec![] }, // INTEGER
                        ifSpeed:           intu32    { name: "ifSpeed".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,5], mutable: false, value: vec![] }, // Gauge
                        ifPhysAddress:     ipv6      { name: "ifPhysAddress".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,6], mutable: false, value: vec![] }, // PhysAddress
                        ifAdminStatus:     inti32    { name: "ifAdminStatus".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,7], mutable: true, value: vec![] }, // INTEGER
                        ifOperStatus:      inti32    { name: "ifOperStatus".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,8], mutable: false, value: vec![] }, // INTEGER
                        ifLastChange:      intu32    { name: "ifLastChange".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,9], mutable: false, value: vec![] }, // TimeTicks
                        ifInOctets:        intu32    { name: "ifInOctets".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,10], mutable: false, value: vec![] }, // Counter
                        ifInUcastPkts:     intu32    { name: "ifInUcastPkts".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,11], mutable: false, value: vec![] }, // Counter
                        ifInNUcastPkts:    intu32    { name: "ifInNUcastPkts".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,12], mutable: false, value: vec![] }, // Counter
                        ifInDiscards:      intu32    { name: "ifInDiscards".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,13], mutable: false, value: vec![] }, // Counter
                        ifInErrors:        intu32    { name: "ifInErrors".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,14], mutable: false, value: vec![] }, // Counter
                        ifInUnknownProtos: intu32    { name: "ifInUnknownProtos".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,15], mutable: false, value: vec![] }, // Counter
                        ifOutOctets:       intu32    { name: "ifOutOctets".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,16], mutable: false, value: vec![] }, // Counter
                        ifOutUcastPkts:    intu32    { name: "ifOutUcastPkts".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,17], mutable: false, value: vec![] }, // Counter
                        ifOutNUcastPkts:   intu32    { name: "ifOutNUcastPkts".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,18], mutable: false, value: vec![] }, // Counter
                        ifOutDiscards:     intu32    { name: "ifOutDiscards".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,19], mutable: false, value: vec![] }, // Counter
                        ifOutErrors:       intu32    { name: "ifOutErrors".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,20], mutable: false, value: vec![] }, // Counter
                        ifOutQLen:         intu32    { name: "ifOutQLen".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,21], mutable: false, value: vec![] }, // Gauge
                        ifSpecific:        oid       { name: "ifSpecific".to_owned(), oid: vec![1,3,6,1,2,1,2,2,1,22], mutable: false, value: vec![] }, // OBJECT_IDENTIFIER
                    } 
                }, 
                at: At {
                    atTable: AtTable {
                        atIfIndex:     inti32    { name: "atIfIndex".to_owned(), oid: vec![1,3,6,1,2,1,3,1,1,1], mutable: true, value: vec![] }, // INTEGER
                        atPhysAddress: ipv6      { name: "atPhysAddress".to_owned(), oid: vec![1,3,6,1,2,1,3,1,1,2], mutable: true, value: vec![] }, // PhysAddress
                        atNetAddress:  ipv4      { name: "atNetAddress".to_owned(), oid: vec![1,3,6,1,2,1,3,1,1,3], mutable: true, value: vec![] }, // IpAddress
                    }
                }, 
                ip: Ip {
                    ipForwarding:      inti32 { name: "ipForwarding".to_owned(), oid: vec![1,3,6,1,2,1,4,1], mutable: true, value: vec![] }, // INTEGER
                    ipDefaultTTL:      inti32 { name: "ipDefaultTTL".to_owned(), oid: vec![1,3,6,1,2,1,4,2], mutable: true, value: vec![] }, // INTEGER
                    ipInReceives:      intu32 { name: "ipInReceives".to_owned(), oid: vec![1,3,6,1,2,1,4,3], mutable: false, value: vec![] }, // Counter
                    ipInHdrErrors:     intu32 { name: "ipInHdrErrors".to_owned(), oid: vec![1,3,6,1,2,1,4,4], mutable: false, value: vec![] }, // Counter
                    ipInAddrErrors:    intu32 { name: "ipInAddrErrors".to_owned(), oid: vec![1,3,6,1,2,1,4,5], mutable: false, value: vec![] }, // Counter
                    ipForwDatagrams:   intu32 { name: "ipForwDatagrams".to_owned(), oid: vec![1,3,6,1,2,1,4,6], mutable: false, value: vec![] }, // Counter
                    ipInUnknownProtos: intu32 { name: "ipInUnknownProtos".to_owned(), oid: vec![1,3,6,1,2,1,4,7], mutable: false, value: vec![] }, // Counter
                    ipInDiscards:      intu32 { name: "ipInDiscards".to_owned(), oid: vec![1,3,6,1,2,1,4,8], mutable: false, value: vec![] }, // Counter
                    ipInDelivers:      intu32 { name: "ipInDelivers".to_owned(), oid: vec![1,3,6,1,2,1,4,9], mutable: false, value: vec![] }, // Counter
                    ipOutRequests:     intu32 { name: "ipOutRequests".to_owned(), oid: vec![1,3,6,1,2,1,4,10], mutable: false, value: vec![] }, // Counter
                    ipOutDiscards:     intu32 { name: "ipOutDiscards".to_owned(), oid: vec![1,3,6,1,2,1,4,11], mutable: false, value: vec![] }, // Counter
                    ipOutNoRoutes:     intu32 { name: "ipOutNoRoutes".to_owned(), oid: vec![1,3,6,1,2,1,4,12], mutable: false, value: vec![] }, // Counter
                    ipReasmTimeout:    inti32 { name: "ipReasmTimeout".to_owned(), oid: vec![1,3,6,1,2,1,4,13], mutable: false, value: vec![] }, // INTEGER
                    ipReasmReqds:      intu32 { name: "ipReasmReqds".to_owned(), oid: vec![1,3,6,1,2,1,4,14], mutable: false, value: vec![] }, // Counter
                    ipReasmOKs:        intu32 { name: "ipReasmOKs".to_owned(), oid: vec![1,3,6,1,2,1,4,15], mutable: false, value: vec![] }, // Counter
                    ipReasmFails:      intu32 { name: "ipReasmFails".to_owned(), oid: vec![1,3,6,1,2,1,4,16], mutable: false, value: vec![] }, // Counter
                    ipFragOKs:         intu32 { name: "ipFragOKs".to_owned(), oid: vec![1,3,6,1,2,1,4,17], mutable: false, value: vec![] }, // Counter
                    ipFragFails:       intu32 { name: "ipFragFails".to_owned(), oid: vec![1,3,6,1,2,1,4,18], mutable: false, value: vec![] }, // Counter
                    ipFragCreates:     intu32 { name: "ipFragCreates".to_owned(), oid: vec![1,3,6,1,2,1,4,19], mutable: false, value: vec![] }, // Counter
                    ipAddrTable: IpAddrTable {
                        ipAdEntAddr:         ipv4       { name: "ipAdEntAddr".to_owned(), oid: vec![1,3,6,1,2,1,4,20,1,1], mutable: false, value: vec![] }, // IpAddress
                        ipAdEntIfIndex:      inti32     { name: "ipAdEntIfIndex".to_owned(), oid: vec![1,3,6,1,2,1,4,20,1,2], mutable: false, value: vec![] }, // INTEGER
                        ipAdEntNetMask:      ipv4       { name: "ipAdEntNetMask".to_owned(), oid: vec![1,3,6,1,2,1,4,20,1,3], mutable: false, value: vec![] }, // IpAddress
                        ipAdEntBcastAddr:    inti32     { name: "ipAdEntBcastAddr".to_owned(), oid: vec![1,3,6,1,2,1,4,20,1,4], mutable: false, value: vec![] }, // INTEGER
                        ipAdEntReasmMaxSize: inti32     { name: "ipAdEntReasmMaxSize".to_owned(), oid: vec![1,3,6,1,2,1,4,20,1,5], mutable: false, value: vec![] }, // INTEGER
                    }, 
                    ipRouteTable: IpRouteTable {
                        ipRouteDest:    ipv4        { name: "ipRouteDest".to_owned(), oid: vec![1,3,6,1,2,1,4,21,1,1], mutable: true, value: vec![] }, // IpAddress
                        ipRouteIfIndex: inti32      { name: "ipRouteIfIndex".to_owned(), oid: vec![1,3,6,1,2,1,4,21,1,2], mutable: true, value: vec![] }, // INTEGER
                        ipRouteMetric1: inti32      { name: "ipRouteMetric1".to_owned(), oid: vec![1,3,6,1,2,1,4,21,1,3], mutable: true, value: vec![] }, // INTEGER
                        ipRouteMetric2: inti32      { name: "ipRouteMetric2".to_owned(), oid: vec![1,3,6,1,2,1,4,21,1,4], mutable: true, value: vec![] }, // INTEGER
                        ipRouteMetric3: inti32      { name: "ipRouteMetric3".to_owned(), oid: vec![1,3,6,1,2,1,4,21,1,5], mutable: true, value: vec![] }, // INTEGER
                        ipRouteMetric4: inti32      { name: "ipRouteMetric4".to_owned(), oid: vec![1,3,6,1,2,1,4,21,1,6], mutable: true, value: vec![] }, // INTEGER
                        ipRouteNextHop: ipv4        { name: "ipRouteNextHop".to_owned(), oid: vec![1,3,6,1,2,1,4,21,1,7], mutable: true, value: vec![] }, // IpAddress
                        ipRouteType:    inti32      { name: "ipRouteType".to_owned(), oid: vec![1,3,6,1,2,1,4,21,1,8], mutable: true, value: vec![] }, // INTEGER
                        ipRouteProto:   inti32      { name: "ipRouteProto".to_owned(), oid: vec![1,3,6,1,2,1,4,21,1,9], mutable: true, value: vec![] }, // INTEGER
                        ipRouteAge:     inti32      { name: "ipRouteAge".to_owned(), oid: vec![1,3,6,1,2,1,4,21,1,10], mutable: true, value: vec![] }, // INTEGER
                        ipRouteMask:    ipv4        { name: "ipRouteMask".to_owned(), oid: vec![1,3,6,1,2,1,4,21,1,11], mutable: true, value: vec![] }, // IpAddress
                        ipRouteMetric5: inti32      { name: "ipRouteMetric5".to_owned(), oid: vec![1,3,6,1,2,1,4,21,1,12], mutable: true, value: vec![] }, // INTEGER
                        ipRouteInfo:    oid         { name: "ipRouteInfo".to_owned(), oid: vec![1,3,6,1,2,1,4,21,1,13], mutable: true, value: vec![] }, // OBJECT_IDENTIFIER
                    }, 
                    ipNetToMediaTable: IpNetToMediaTable {
                        ipNetToMediaIfIndex:     inti32     { name: "ipNetToMediaIfIndex".to_owned(), oid: vec![1,3,6,1,2,1,4,22,1,1], mutable: true, value: vec![] }, // INTEGER
                        ipNetToMediaPhysAddress: ipv6       { name: "ipNetToMediaPhysAddress".to_owned(), oid: vec![1,3,6,1,2,1,4,22,1,2], mutable: true, value: vec![] }, // PhysAddress
                        ipNetToMediaNetAddress:  ipv4       { name: "ipNetToMediaNetAddress".to_owned(), oid: vec![1,3,6,1,2,1,4,22,1,3], mutable: true, value: vec![] }, // IpAddress
                        ipNetToMediaType:        inti32     { name: "ipNetToMediaType".to_owned(), oid: vec![1,3,6,1,2,1,4,22,1,4], mutable: true, value: vec![] }, // INTEGER
                    }, 
                    ipRoutingDiscards: intu32 { name: "ipRoutingDiscards".to_owned(), oid: vec![1,3,6,1,2,1,4,23], mutable: false, value: vec![] }, // Counter
                }, 
                icmp: Icmp {
                    icmpInMsgs:           intu32 { name: "icmpInMsgs".to_owned(),           oid: vec![1,3,6,1,2,1,5,1], mutable: false, value: vec![] }, // Counter
                    icmpInErrors:         intu32 { name: "icmpInErrors".to_owned(),         oid: vec![1,3,6,1,2,1,5,2], mutable: false, value: vec![] }, // Counter
                    icmpInDestUnreachs:   intu32 { name: "icmpInDestUnreachs".to_owned(),   oid: vec![1,3,6,1,2,1,5,3], mutable: false, value: vec![] }, // Counter
                    icmpInTimeExcds:      intu32 { name: "icmpInTimeExcds".to_owned(),      oid: vec![1,3,6,1,2,1,5,4], mutable: false, value: vec![] }, // Counter
                    icmpInParmProbs:      intu32 { name: "icmpInParmProbs".to_owned(),      oid: vec![1,3,6,1,2,1,5,5], mutable: false, value: vec![] }, // Counter
                    icmpInSrcQuenchs:     intu32 { name: "icmpInSrcQuenchs".to_owned(),     oid: vec![1,3,6,1,2,1,5,6], mutable: false, value: vec![] }, // Counter
                    icmpInRedirects:      intu32 { name: "icmpInRedirects".to_owned(),      oid: vec![1,3,6,1,2,1,5,7], mutable: false, value: vec![] }, // Counter
                    icmpInEchos:          intu32 { name: "icmpInEchos".to_owned(),          oid: vec![1,3,6,1,2,1,5,8], mutable: false, value: vec![] }, // Counter
                    icmpInEchoReps:       intu32 { name: "icmpInEchoReps".to_owned(),       oid: vec![1,3,6,1,2,1,5,9], mutable: false, value: vec![] }, // Counter
                    icmpInTimestamps:     intu32 { name: "icmpInTimestamps".to_owned(),     oid: vec![1,3,6,1,2,1,5,10], mutable: false, value: vec![] }, // Counter
                    icmpInTimestampReps:  intu32 { name: "icmpInTimestampReps".to_owned(),  oid: vec![1,3,6,1,2,1,5,11], mutable: false, value: vec![] }, // counter
                    icmpInAddrMasks:      intu32 { name: "icmpInAddrMasks".to_owned(),      oid: vec![1,3,6,1,2,1,5,12], mutable: false, value: vec![] }, // Counter
                    icmpInAddrMaskReps:   intu32 { name: "icmpInAddrMaskReps".to_owned(),   oid: vec![1,3,6,1,2,1,5,13], mutable: false, value: vec![] }, // counter
                    icmpOutMsgs:          intu32 { name: "icmpOutMsgs".to_owned(),          oid: vec![1,3,6,1,2,1,5,14], mutable: false, value: vec![] }, // Counter
                    icmpOutErrors:        intu32 { name: "icmpOutErrors".to_owned(),        oid: vec![1,3,6,1,2,1,5,15], mutable: false, value: vec![] }, // Counter
                    icmpOutDestUnreachs:  intu32 { name: "icmpOutDestUnreachs".to_owned(),  oid: vec![1,3,6,1,2,1,5,16], mutable: false, value: vec![] }, // counter
                    icmpOutTimeExcds:     intu32 { name: "icmpOutTimeExcds".to_owned(),     oid: vec![1,3,6,1,2,1,5,17], mutable: false, value: vec![] }, // Counter
                    icmpOutParmProbs:     intu32 { name: "icmpOutParmProbs".to_owned(),     oid: vec![1,3,6,1,2,1,5,18], mutable: false, value: vec![] }, // Counter
                    icmpOutSrcQuenchs:    intu32 { name: "icmpOutSrcQuenchs".to_owned(),    oid: vec![1,3,6,1,2,1,5,19], mutable: false, value: vec![] }, // Counter
                    icmpOutRedirects:     intu32 { name: "icmpOutRedirects".to_owned(),     oid: vec![1,3,6,1,2,1,5,20], mutable: false, value: vec![] }, // Counter
                    icmpOutEchos:         intu32 { name: "icmpOutEchos".to_owned(),         oid: vec![1,3,6,1,2,1,5,21], mutable: false, value: vec![] }, // Counter
                    icmpOutEchoReps:      intu32 { name: "icmpOutEchoReps".to_owned(),      oid: vec![1,3,6,1,2,1,5,22], mutable: false, value: vec![] }, // Counter
                    icmpOutTimestamps:    intu32 { name: "icmpOutTimestamps".to_owned(),    oid: vec![1,3,6,1,2,1,5,23], mutable: false, value: vec![] }, // Counter
                    icmpOutTimestampReps: intu32 { name: "icmpOutTimestampReps".to_owned(), oid: vec![1,3,6,1,2,1,5,24], mutable: false, value: vec![] }, // counter
                    icmpOutAddrMasks:     intu32 { name: "icmpOutAddrMasks".to_owned(),     oid: vec![1,3,6,1,2,1,5,25], mutable: false, value: vec![] }, // Counter
                    icmpOutAddrMaskReps:  intu32 { name: "icmpOutAddrMaskReps".to_owned(),  oid: vec![1,3,6,1,2,1,5,26], mutable: false, value: vec![] }, // counter
                }, 
                tcp: Tcp {
                    tcpRtoAlgorithm: inti32 { name: "tcpRtoAlgorithm".to_owned(), oid: vec![1,3,6,1,2,1,6,1], mutable: false, value: vec![] }, // INTEGER
                    tcpRtoMin:       inti32 { name: "tcpRtoMin".to_owned(), oid: vec![1,3,6,1,2,1,6,2], mutable: false, value: vec![] }, // INTEGER
                    tcpRtoMax:       inti32 { name: "tcpRtoMax".to_owned(), oid: vec![1,3,6,1,2,1,6,3], mutable: false, value: vec![] }, // INTEGER
                    tcpMaxConn:      inti32 { name: "tcpMaxConn".to_owned(), oid: vec![1,3,6,1,2,1,6,4], mutable: false, value: vec![] }, // INTEGER
                    tcpActiveOpens:  intu32 { name: "tcpActiveOpens".to_owned(), oid: vec![1,3,6,1,2,1,6,5], mutable: false, value: vec![] }, // Counter
                    tcpPassiveOpens: intu32 { name: "tcpPassiveOpens".to_owned(), oid: vec![1,3,6,1,2,1,6,6], mutable: false, value: vec![] }, // Counter
                    tcpAttemptFails: intu32 { name: "tcpAttemptFails".to_owned(), oid: vec![1,3,6,1,2,1,6,7], mutable: false, value: vec![] }, // Counter
                    tcpEstabResets:  intu32 { name: "tcpEstabResets".to_owned(), oid: vec![1,3,6,1,2,1,6,8], mutable: false, value: vec![] }, // Counter
                    tcpCurrEstab:    intu32 { name: "tcpCurrEstab".to_owned(), oid: vec![1,3,6,1,2,1,6,9], mutable: false, value: vec![] }, // Gauge
                    tcpInSegs:       intu32 { name: "tcpInSegs".to_owned(), oid: vec![1,3,6,1,2,1,6,10], mutable: false, value: vec![] }, // Counter
                    tcpOutSegs:      intu32 { name: "tcpOutSegs".to_owned(), oid: vec![1,3,6,1,2,1,6,11], mutable: false, value: vec![] }, // Counter
                    tcpRetransSegs:  intu32 { name: "tcpRetransSegs".to_owned(), oid: vec![1,3,6,1,2,1,6,12], mutable: false, value: vec![] }, // Counter
                    tcpConnTable: TcpConnTable {
                        tcpConnState:        inti32     { name: "tcpConnState".to_owned(), oid: vec![1,3,6,1,2,1,6,13,1,1], mutable: true, value: vec![] }, // INTEGER
                        tcpConnLocalAddress: ipv4       { name: "tcpConnLocalAddress".to_owned(), oid: vec![1,3,6,1,2,1,6,13,1,2], mutable: false, value: vec![] }, // IpAddress
                        tcpConnLocalPort:    inti32     { name: "tcpConnLocalPort".to_owned(), oid: vec![1,3,6,1,2,1,6,13,1,3], mutable: false, value: vec![] }, // INTEGER
                        tcpConnRemAddress:   ipv4       { name: "tcpConnRemAddress".to_owned(), oid: vec![1,3,6,1,2,1,6,13,1,4], mutable: false, value: vec![] }, // IpAddress
                        tcpConnRemPort:      inti32     { name: "tcpConnRemPort".to_owned(), oid: vec![1,3,6,1,2,1,6,13,1,5], mutable: false, value: vec![] }, // INTEGER
                    }, 
                    tcpInErrs: intu32  { name: "tcpInErrs".to_owned(), oid: vec![1,3,6,1,2,1,6,14], mutable: false, value: vec![] }, // Counter
                    tcpOutRsts: intu32 { name: "tcpOutRsts".to_owned(), oid: vec![1,3,6,1,2,1,6,15], mutable: false, value: vec![] }, // Counter
                }, 
                udp: Udp {
                    udpInDatagrams:  intu32 { name: "udpInDatagrams".to_owned(), oid: vec![1,3,6,1,2,1,7,1], mutable: false, value: vec![] }, // Counter
                    udpNoPorts:      intu32 { name: "udpNoPorts".to_owned(), oid: vec![1,3,6,1,2,1,7,2], mutable: false, value: vec![] }, // Counter
                    udpInErrors:     intu32 { name: "udpInErrors".to_owned(), oid: vec![1,3,6,1,2,1,7,3], mutable: false, value: vec![] }, // Counter
                    udpOutDatagrams: intu32 { name: "udpOutDatagrams".to_owned(), oid: vec![1,3,6,1,2,1,7,4], mutable: false, value: vec![] }, // Counter
                    udpTable: UdpTable {
                        udpLocalAddress: ipv4            { name: "udpLocalAddress".to_owned(), oid: vec![1,3,6,1,2,1,7,5,1,1], mutable: false, value: vec![] }, // IpAddress
                        udpLocalPort:    inti32     { name: "udpLocalPort".to_owned(), oid: vec![1,3,6,1,2,1,7,5,1,2], mutable: false, value: vec![] }, // INTEGER
                    } 
                }, 
                egp: Egp {
                    egpInMsgs:    intu32 { name: "egpInMsgs".to_owned(), oid: vec![1,3,6,1,2,1,8,1], mutable: false, value: vec![] }, // Counter
                    egpInErrors:  intu32 { name: "egpInErrors".to_owned(), oid: vec![1,3,6,1,2,1,8,2], mutable: false, value: vec![] }, // Counter
                    egpOutMsgs:   intu32 { name: "egpOutMsgs".to_owned(), oid: vec![1,3,6,1,2,1,8,3], mutable: false, value: vec![] }, // Counter
                    egpOutErrors: intu32 { name: "egpOutErrors".to_owned(), oid: vec![1,3,6,1,2,1,8,4], mutable: false, value: vec![] }, // Counter
                    egpNeighTable: EgpNeighTable {
                        egpNeighState:         inti32       { name: "egpNeighState".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,1], mutable: false, value: vec![] }, // INTEGER
                        egpNeighAddr:          ipv4         { name: "egpNeighAddr".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,2], mutable: false, value: vec![] }, // IpAddress
                        egpNeighAs:            inti32       { name: "egpNeighAs".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,3], mutable: false, value: vec![] }, // INTEGER
                        egpNeighInMsgs:        intu32       { name: "egpNeighInMsgs".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,4], mutable: false, value: vec![] }, // Counter
                        egpNeighInErrs:        intu32       { name: "egpNeighInErrs".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,5], mutable: false, value: vec![] }, // Counter
                        egpNeighOutMsgs:       intu32       { name: "egpNeighOutMsgs".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,6], mutable: false, value: vec![] }, // Counter
                        egpNeighOutErrs:       intu32       { name: "egpNeighOutErrs".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,7], mutable: false, value: vec![] }, // Counter
                        egpNeighInErrMsgs:     intu32       { name: "egpNeighInErrMsgs".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,8], mutable: false, value: vec![] }, // Counter
                        egpNeighOutErrMsgs:    intu32       { name: "egpNeighOutErrMsgs".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,9], mutable: false, value: vec![] }, // Counter
                        egpNeighStateUps:      intu32       { name: "egpNeighStateUps".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,10], mutable: false, value: vec![] }, // Counter
                        egpNeighStateDowns:    intu32       { name: "egpNeighStateDowns".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,11], mutable: false, value: vec![] }, // Counter
                        egpNeighIntervalHello: inti32       { name: "egpNeighIntervalHello".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,12], mutable: false, value: vec![] }, // INTEGER
                        egpNeighIntervalPoll:  inti32       { name: "egpNeighIntervalPoll".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,13], mutable: false, value: vec![] }, // INTEGER
                        egpNeighMode:          inti32       { name: "egpNeighMode".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,14], mutable: false, value: vec![] }, // INTEGER
                        egpNeighEventTrigger:  inti32       { name: "egpNeighEventTrigger".to_owned(), oid: vec![1,3,6,1,2,1,8,5,1,15], mutable: true, value: vec![] }, // INTEGER
                    }, 
                    egpAs: inti32 { name: "egpAs".to_owned(), oid: vec![1,3,6,1,2,1,8,6], mutable: false, value: vec![] }, // INTEGER
                }, 
                transmission: oid { name: "transmission".to_owned(), oid: vec![1,3,6,1,2,1,10], mutable: false, value: vec![] }, // objectidentity
                snmp: Snmp {
                    snmpInPkts:              intu32 { name: "snmpInPkts".to_owned(), oid: vec![1,3,6,1,2,1,11,1], mutable: false, value: vec![] }, // Counter
                    snmpOutPkts:             intu32 { name: "snmpOutPkts".to_owned(), oid: vec![1,3,6,1,2,1,11,2], mutable: false, value: vec![] }, // Counter
                    snmpInBadVersions:       intu32 { name: "snmpInBadVersions".to_owned(), oid: vec![1,3,6,1,2,1,11,3], mutable: false, value: vec![] }, // Counter
                    snmpInBadCommunityNames: intu32 { name: "snmpInBadCommunityNames".to_owned(), oid: vec![1,3,6,1,2,1,11,4], mutable: false, value: vec![] }, // Counter
                    snmpInBadCommunityUses:  intu32 { name: "snmpInBadCommunityUses".to_owned(), oid: vec![1,3,6,1,2,1,11,5], mutable: false, value: vec![] }, // Counter
                    snmpInASNParseErrs:      intu32 { name: "snmpInASNParseErrs".to_owned(), oid: vec![1,3,6,1,2,1,11,6], mutable: false, value: vec![] }, // Counter
                    snmpInTooBigs:           intu32 { name: "snmpInTooBigs".to_owned(), oid: vec![1,3,6,1,2,1,11,8], mutable: false, value: vec![] }, // Counter
                    snmpInNoSuchNames:       intu32 { name: "snmpInNoSuchNames".to_owned(), oid: vec![1,3,6,1,2,1,11,9], mutable: false, value: vec![] }, // Counter
                    snmpInBadValues:         intu32 { name: "snmpInBadValues".to_owned(), oid: vec![1,3,6,1,2,1,11,10], mutable: false, value: vec![] }, // Counter
                    snmpInReadOnlys:         intu32 { name: "snmpInReadOnlys".to_owned(), oid: vec![1,3,6,1,2,1,11,11], mutable: false, value: vec![] }, // Counter
                    snmpInGenErrs:           intu32 { name: "snmpInGenErrs".to_owned(), oid: vec![1,3,6,1,2,1,11,12], mutable: false, value: vec![] }, // Counter
                    snmpInTotalReqVars:      intu32 { name: "snmpInTotalReqVars".to_owned(), oid: vec![1,3,6,1,2,1,11,13], mutable: false, value: vec![] }, // Counter
                    snmpInTotalSetVars:      intu32 { name: "snmpInTotalSetVars".to_owned(), oid: vec![1,3,6,1,2,1,11,14], mutable: false, value: vec![] }, // Counter
                    snmpInGetRequests:       intu32 { name: "snmpInGetRequests".to_owned(), oid: vec![1,3,6,1,2,1,11,15], mutable: false, value: vec![] }, // Counter
                    snmpInGetNexts:          intu32 { name: "snmpInGetNexts".to_owned(), oid: vec![1,3,6,1,2,1,11,16], mutable: false, value: vec![] }, // Counter
                    snmpInSetRequests:       intu32 { name: "snmpInSetRequests".to_owned(), oid: vec![1,3,6,1,2,1,11,17], mutable: false, value: vec![] }, // Counter
                    snmpInGetResponses:      intu32 { name: "snmpInGetResponses".to_owned(), oid: vec![1,3,6,1,2,1,11,18], mutable: false, value: vec![] }, // Counter
                    snmpInTraps:             intu32 { name: "snmpInTraps".to_owned(), oid: vec![1,3,6,1,2,1,11,19], mutable: false, value: vec![] }, // Counter
                    snmpOutTooBigs:          intu32 { name: "snmpOutTooBigs".to_owned(), oid: vec![1,3,6,1,2,1,11,20], mutable: false, value: vec![] }, // Counter
                    snmpOutNoSuchNames:      intu32 { name: "snmpOutNoSuchNames".to_owned(), oid: vec![1,3,6,1,2,1,11,21], mutable: false, value: vec![] }, // Counter
                    snmpOutBadValues:        intu32 { name: "snmpOutBadValues".to_owned(), oid: vec![1,3,6,1,2,1,11,22], mutable: false, value: vec![] }, // Counter
                    snmpOutGenErrs:          intu32 { name: "snmpOutGenErrs".to_owned(), oid: vec![1,3,6,1,2,1,11,24], mutable: false, value: vec![] }, // Counter
                    snmpOutGetRequests:      intu32 { name: "snmpOutGetRequests".to_owned(), oid: vec![1,3,6,1,2,1,11,25], mutable: false, value: vec![] }, // Counter
                    snmpOutGetNexts:         intu32 { name: "snmpOutGetNexts".to_owned(), oid: vec![1,3,6,1,2,1,11,26], mutable: false, value: vec![] }, // Counter
                    snmpOutSetRequests:      intu32 { name: "snmpOutSetRequests".to_owned(), oid: vec![1,3,6,1,2,1,11,27], mutable: false, value: vec![] }, // Counter
                    snmpOutGetResponses:     intu32 { name: "snmpOutGetResponses".to_owned(), oid: vec![1,3,6,1,2,1,11,28], mutable: false, value: vec![] }, // Counter
                    snmpOutTraps:            intu32 { name: "snmpOutTraps".to_owned(), oid: vec![1,3,6,1,2,1,11,29], mutable: false, value: vec![] }, // Counter
                    snmpEnableAuthenTraps:   inti32 { name: "snmpEnableAuthenTraps".to_owned(), oid: vec![1,3,6,1,2,1,11,30], mutable: true, value: vec![] }, // INTEGER
                } 
            }
        }
    }
    
















    
    #[derive(Serialize, Deserialize)]
    pub struct MibString { 
        pub name: String, 
        pub oid: Vec<u8>, 
        pub mutable: bool, 
        pub value: Vec<String> 
    }
    
    #[derive(Serialize, Deserialize)]
    pub struct inti32 { 
        pub name: String, 
        pub oid: Vec<u8>, 
        pub mutable: bool, 
        pub value: Vec<i32> 
    }
    
    #[derive(Serialize, Deserialize)]
    pub struct intu32 { 
        pub name: String, 
        pub oid: Vec<u8>, 
        pub mutable: bool, 
        pub value: Vec<u32> 
    }
    
    #[derive(Serialize, Deserialize)]
    pub struct intu64 { 
        pub name: String, 
        pub oid: Vec<u8>, 
        pub mutable: bool, 
        pub value: Vec<u64> 
    }
    
    #[derive(Serialize, Deserialize)]
    pub struct oid { 
        pub name: String, 
        pub oid: Vec<u8>, 
        pub mutable: bool, 
        pub value: Vec<Vec<u8>> 
    }
    
    #[derive(Serialize, Deserialize)]
    pub struct ipv4 { 
        pub name: String, 
        pub oid: Vec<u8>, 
        pub mutable: bool, 
        pub value: Vec<(u8,u8,u8,u8)> 
    }
    
    #[derive(Serialize, Deserialize)]
    pub struct mac { 
        pub name: String, 
        pub oid: Vec<u8>, 
        pub mutable: bool, 
        pub value: Vec<(u16,u16,u16,u16,u16,u16)> 
    }
    
    #[derive(Serialize, Deserialize)]
    pub struct ipv6 { 
        pub name: String, 
        pub oid: Vec<u8>, 
        pub mutable: bool, 
        pub value: Vec<(u16,u16,u16,u16,u16,u16,u16,u16)> 
    }

    impl Clone for MibString {
        fn clone(&self) -> Self {
            MibString { 
                name:    self.name.clone(), 
                oid:     self.oid.to_owned(), 
                mutable: self.mutable.clone(), 
                value:   self.value.to_owned(), 
            }
        }
    }
    
    impl Clone for inti32 {
        fn clone(&self) -> Self {
            inti32 { 
                name:    self.name.clone(), 
                oid:     self.oid.to_owned(), 
                mutable: self.mutable.clone(), 
                value:   self.value.to_owned(), 
            }
        }
    }
    
    impl Clone for intu32 {
        fn clone(&self) -> Self {
            intu32 { 
                name:    self.name.clone(), 
                oid:     self.oid.to_owned(), 
                mutable: self.mutable.clone(), 
                value:   self.value.to_owned(), 
            }
        }
    }
    
    impl Clone for intu64 {
        fn clone(&self) -> Self {
            intu64 { 
                name:    self.name.clone(), 
                oid:     self.oid.to_owned(), 
                mutable: self.mutable.clone(), 
                value:   self.value.to_owned(), 
            }
        }
    }
    
    impl Clone for oid {
        fn clone(&self) -> Self {
            oid { 
                name:    self.name.clone(), 
                oid:     self.oid.to_owned(), 
                mutable: self.mutable.clone(), 
                value:   self.value.to_owned(), 
            }
        }
    }
    
    impl Clone for ipv4 {
        fn clone(&self) -> Self {
            ipv4 { 
                name:    self.name.clone(), 
                oid:     self.oid.to_owned(), 
                mutable: self.mutable.clone(), 
                value:   self.value.to_owned(), 
            }
        }
    }
    
    impl Clone for mac {
        fn clone(&self) -> Self {
            mac { 
                name:    self.name.clone(), 
                oid:     self.oid.to_owned(), 
                mutable: self.mutable.clone(), 
                value:   self.value.to_owned(), 
            }
        }
    }
    
    impl Clone for ipv6 {
        fn clone(&self) -> Self {
            ipv6 { 
                name:    self.name.clone(), 
                oid:     self.oid.to_owned(), 
                mutable: self.mutable.clone(), 
                value:   self.value.to_owned(), 
            }
        }
    }

    #[async_trait]
    pub trait MibValue {
        fn oid(&self) -> String;
        async fn walk(&mut self, client: &Snmp2cClient)-> Option<String>;
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
                                {
                                    match a.1.as_i32() {
                                        Some(res) => {
                                            res
                                        },
                                        None => 0,
                                    }
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
                            self.value = res.into_iter().map(|a| {
                                // println!("ipv4 res: \n{:?}, {:?}", a.1, a.1.as_ipv4());
                                match a.1.as_ipv4() {
                                        Some(res) => {
                                            let c = res.octets();
                                            if c.len() == 4 {
                                                return (c[0],c[1],c[2],c[3])
                                            } else {
                                                return (0,0,0,0)
                                            }
                                        },
                                        None => return (0,0,0,0),
                                    };
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
                                        // println!("mac res: {:?}", res);
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
                                        // println!("ipv6 res: {:?}", res);
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
    
    
}