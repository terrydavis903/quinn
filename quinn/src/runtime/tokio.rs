use std::{
    future::Future, io, net::SocketAddr, pin::Pin, task::{Context, Poll}, time::Instant
};

use byteorder::{BigEndian, WriteBytesExt};
use log::{debug, info};
use tokio::{
    io::Interest,
    time::{sleep_until, Sleep},
};
use udp::Transmit;

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
    // fn proxy_send(
    //     &self,
    //     state: &udp::UdpState,
    //     cx: &mut Context,
    //     transmits: &[udp::Transmit]
    // ) -> Poll<io::Result<usize>> {
    //     let inner = &self.inner;
    //     let io = &self.io;
    //     loop {
    //         // ready!(io.poll_send_ready(cx))?;
    //         // if let Ok(res) = io.try_io(Interest::WRITABLE, || {
    //         //     debug!("poll sending packets: {}", transmits.len());
    //         //     inner.send_proxy(io.into(), state, transmits)
    //         //     // inner.send(io.into(), state, &to_send)
    //         // }) {
    //         //     return Poll::Ready(Ok(res));
    //         // }
            
    //         debug!("poll sending packets: {}", transmits.len());
    //         if let Ok(res) = inner.send_proxy(io.into(), state, transmits){
    //             return Poll::Ready(Ok(res));
    //         }
            
    //     }
    // }

    // fn proxy_recv(
    //     &self,
    //     cx: &mut Context,
    //     bufs: &mut [std::io::IoSliceMut<'_>],
    //     meta: &mut [udp::RecvMeta]
    // ) -> Poll<io::Result<usize>> {
    //     loop {
    //         // ready!(self.io.poll_recv_ready(cx))?;
            
    //         // let io_res = self.io.try_io(Interest::READABLE, || {
    //         //     // self.inner.recv((&self.io).into(), bufs, meta)
    //         // });
    //         // debug!("tokio recieved");

    //         let io_res = self.inner.recv_proxy((&self.io).into(), bufs, meta);
            
    //         if let Ok(res) = io_res{
    //             if res != 0{
    //                 info!("tokio recieved: {} msgs", res);
    //             }
    //             return Poll::Ready(Ok(res));
    //         }else
    //         if let Err(res_err) = io_res{
    //             info!("tokio proxy rec error: {}", res_err);
    //             return Poll::Ready(Err(res_err));
    //         }

    //         // debug!("should be unreachable: {:?}", io_res);
    //     }
    // }

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
            debug!("poll sending packets: {}", transmits.len());

            if let Ok(res) = io.try_io(Interest::WRITABLE, || {
                inner.send(io.into(), state, transmits)
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
                self.inner.recv((&self.io).into(), bufs, meta)
            }) {
                if res != 0{
                    info!("tokio recieved: {} msgs", res);
                }
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
            debug!("poll sending packets: {}", transmits.len());
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
                if res != 0{
                    info!("tokio recieved: {} msgs", res);
                }
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

    fn reconnect(&self, proxy_addr: SocketAddr) -> io::Result<()>  {
        let inner = &self.inner;
        let io = &self.io;
        inner.connect_socket(io.into(), &proxy_addr)
    }
}