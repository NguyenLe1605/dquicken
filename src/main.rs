use dquicken::packet::*;
fn main() {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("127.0.0.1:2803").unwrap();
    let mut buf = [0; 1350];
    let (amt, src) = socket.recv_from(&mut buf).unwrap();
    // Redeclare `buf` as slice of the received data and send reverse data back to origin.
    let buf = &mut buf[..amt];
    let header = LongHeader::from_slice(buf);
    println!("{:?}", header);
    buf.reverse();
    socket.send_to(buf, src).unwrap();
}
