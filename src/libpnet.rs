use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::packet::tcp::TcpPacket;
use core::PacketHeader;
use core;

fn convert_packet<'a>(datalink_type: i32, _header: PacketHeader, packet_data: Vec<u8>) -> EthernetPacket<'a> {
    if datalink_type != 1 {
        panic!("Not reading Ethernet packets");
    }

    EthernetPacket::owned(packet_data).unwrap()
}

pub fn test() {
    match core::find_all_devs() {
        Ok(pcap_ifs) => pcap_ifs.for_each(|interface| println!("{:?}", interface)),
        Err(e) => println!("{:?}", e)
    }

    // 0 will use pcap default
    // For old versions the default was 68 bytes
    // Later it was increased to 65535 bytes
    // And in the most recent versions it is 262144 bytes
    let default_snaplen = 0;

    // 0 will loop forever
    // Any other positive number will exit after that many packets have been received
    let num_packets = 0;
    match core::open_live("en0", default_snaplen, true, 10) {
        Ok(handle) => {
            let mut filter = handle.compile("tcp port 443", true, 0);
            handle.setfilter(&mut filter);
            handle.loop_(0, |header, packet| {
                let packet = convert_packet(1, header, packet);
                match packet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let ipv4_packet = Ipv4Packet::owned(packet.payload().to_vec()).unwrap();
                        let tcp_packet = TcpPacket::owned(ipv4_packet.payload().to_vec()).unwrap();
                        println!("{:?}", tcp_packet);
                    }
                    EtherTypes::Ipv6 => {
                        let ipv6_packet = Ipv6Packet::owned(packet.payload().to_vec()).unwrap();
                        let tcp_packet = TcpPacket::owned(ipv6_packet.payload().to_vec()).unwrap();
                        println!("{:?}", tcp_packet);
                    }
                    other => println!("Unhandled ethertype: {:?}", other)
                }
            })
        }
        Err(e) => println!("{:?}", e)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        super::test();
        assert_eq!(2 + 2, 4);
    }
}
