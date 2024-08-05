use std::{
    future::Future, io, net::SocketAddr, pin::Pin, task::{Context, Poll}, time::Instant
};

use byteorder::{BigEndian, WriteBytesExt};
use log::debug;
use tokio::{
    io::Interest,
    time::{sleep_until, Sleep},
};

use super::{AsyncTimer, AsyncUdpSocket, Runtime};

/// A Quinn runtime for Tokio
#[derive(Debug)]
pub struct TokioRuntime;

impl Runtime for TokioRuntime {
    fn new_timer(&self, t: Instant) -> Pin<Box<dyn AsyncTimer>> {
        Box::pin(sleep_until(t.into()))
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, sock: std::net::UdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>> {
        udp::UdpSocketState::configure((&sock).into())?;
        Ok(Box::new(UdpSocket {
            io: tokio::net::UdpSocket::from_std(sock)?,
            inner: udp::UdpSocketState::new(),
        }))
    }
}


impl AsyncTimer for Sleep {
    fn reset(self: Pin<&mut Self>, t: Instant) {
        Self::reset(self, t.into())
    }
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<()> {
        Future::poll(self, cx)
    }
}

#[derive(Debug)]
struct UdpSocket {
    io: tokio::net::UdpSocket,
    inner: udp::UdpSocketState,
}

impl AsyncUdpSocket for UdpSocket {
    fn proxy_send(
        &self,
        state: &udp::UdpState,
        cx: &mut Context,
        transmits: &[udp::Transmit],
    ) -> Poll<io::Result<usize>> {
        let inner = &self.inner;
        let io = &self.io;
        loop {
            ready!(io.poll_send_ready(cx))?;
            if let Ok(res) = io.try_io(Interest::WRITABLE, || {
                // for transmit in transmits{

                //     let mut header = [0; 260 + 3];
                //     let mut fwd_hdr: &mut [u8] = &mut header[3..];

                //     let start_len = fwd_hdr.len();

                //     match transmit.destination {
                //         SocketAddr::V4(v4_addr) => {
                //             fwd_hdr.write_u8(1).unwrap();
                //             fwd_hdr.write_u32::<BigEndian>((*v4_addr.ip()).into()).unwrap();
                //             fwd_hdr.write_u16::<BigEndian>(v4_addr.port()).unwrap();
                //         },
                //         _ => {

                //         }
                //     };

                //     let written_len = fwd_hdr.len();

                //     let header_len = ((start_len - written_len) + 3) as usize;
                //     let mut write_buffer = vec![];
                //     write_buffer.extend_from_slice(&header[..header_len]);
                //     write_buffer.extend_from_slice(&transmit.contents);

                //     self.io.try_send(&write_buffer).unwrap();
                // }
                inner.send_proxy(io.into(), state, transmits)
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn proxy_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv_proxy((&self.io).into(), bufs, meta)
            }) {
                debug!("async tokio proxy rec read: {} messages", res);
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn poll_send(
        &self,
        state: &udp::UdpState,
        cx: &mut Context,
        transmits: &[udp::Transmit],
    ) -> Poll<io::Result<usize>> {
        let inner = &self.inner;
        let io = &self.io;
        loop {
            ready!(io.poll_send_ready(cx))?;
            if let Ok(res) = io.try_io(Interest::WRITABLE, || {
                inner.send(io.into(), state, transmits)
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            
            if let Ok(res) = self.io.try_io(Interest::READABLE, || {
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                return Poll::Ready(Ok(res));
            }
        }
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        udp::may_fragment()
    }
}