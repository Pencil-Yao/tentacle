use crate::{error::TransportErrorKind, multiaddr::Multiaddr, utils::socketaddr_to_multiaddr};

use futures::{prelude::Stream, FutureExt};
use log::debug;
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    prelude::{AsyncRead, AsyncWrite},
};

use self::tcp::{TcpDialFuture, TcpListenFuture, TcpTransport};
use tokio_rustls::webpki::DNSNameRef;
use tokio_rustls::{client, server, TlsAcceptor, TlsConnector};

mod tcp;

type Result<T> = std::result::Result<T, TransportErrorKind>;

/// Definition of transport protocol behavior
pub trait Transport {
    type ListenFuture;
    type DialFuture;

    /// Transport listen
    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture>;
    /// Transport dial
    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture>;
}

#[derive(Clone, Copy)]
pub struct MultiTransport {
    timeout: Duration,
}

impl MultiTransport {
    pub fn new(timeout: Duration) -> Self {
        MultiTransport { timeout }
    }
}

impl Transport for MultiTransport {
    type ListenFuture = MultiListenFuture;
    type DialFuture = MultiDialFuture;

    fn listen(self, address: Multiaddr) -> Result<Self::ListenFuture> {
        match TcpTransport::new(self.timeout).listen(address) {
            Ok(future) => Ok(MultiListenFuture::Tcp(future)),
            Err(e) => Err(e),
        }
    }

    fn dial(self, address: Multiaddr) -> Result<Self::DialFuture> {
        match TcpTransport::new(self.timeout).dial(address) {
            Ok(res) => Ok(MultiDialFuture::Tcp(res)),
            Err(e) => Err(e),
        }
    }
}

pub enum MultiListenFuture {
    Tcp(TcpListenFuture),
}

impl Future for MultiListenFuture {
    type Output = Result<(Multiaddr, MultiIncoming)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            MultiListenFuture::Tcp(inner) => {
                Pin::new(&mut inner.map(|res| res.map(|res| (res.0, MultiIncoming::Tcp(res.1)))))
                    .poll(cx)
            }
        }
    }
}

pub enum MultiDialFuture {
    Tcp(TcpDialFuture),
}

impl Future for MultiDialFuture {
    type Output = Result<(Multiaddr, MultiStream)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            MultiDialFuture::Tcp(inner) => {
                Pin::new(&mut inner.map(|res| res.map(|res| (res.0, MultiStream::Tcp(res.1)))))
                    .poll(cx)
            }
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum MultiStream {
    Tcp(TcpStream),
    TlsServer(server::TlsStream<TcpStream>),
    TlsClient(client::TlsStream<TcpStream>),
}

impl MultiStream {
    pub async fn accept(self, acceptor: TlsAcceptor) -> Result<MultiStream> {
        if let MultiStream::Tcp(inner) = self {
            Ok(MultiStream::TlsServer(
                acceptor
                    .accept(inner)
                    .await
                    .map_err(|e| TransportErrorKind::Io(e))?,
            ))
        } else {
            Err(TransportErrorKind::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stream is no TcpStream",
            )))
        }
    }

    pub async fn connect(self, connector: TlsConnector, domain: &str) -> Result<MultiStream> {
        if let MultiStream::Tcp(inner) = self {
            let domain = DNSNameRef::try_from_ascii_str(domain).map_err(|_| {
                TransportErrorKind::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid dnsname",
                ))
            })?;
            Ok(MultiStream::TlsClient(
                connector
                    .connect(domain, inner)
                    .await
                    .map_err(|e| TransportErrorKind::Io(e))?,
            ))
        } else {
            Err(TransportErrorKind::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stream is no TcpStream",
            )))
        }
    }
}

impl fmt::Debug for MultiStream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MultiStream::Tcp(_) => write!(f, "Tcp stream"),
            MultiStream::TlsServer(_) => write!(f, "Tls server stream"),
            MultiStream::TlsClient(_) => write!(f, "Tls client stream"),
        }
    }
}

impl AsyncRead for MultiStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MultiStream::Tcp(inner) => Pin::new(inner).poll_read(cx, buf),
            MultiStream::TlsServer(inner) => Pin::new(inner).poll_read(cx, buf),
            MultiStream::TlsClient(inner) => Pin::new(inner).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MultiStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MultiStream::Tcp(inner) => Pin::new(inner).poll_write(cx, buf),
            MultiStream::TlsServer(inner) => Pin::new(inner).poll_write(cx, buf),
            MultiStream::TlsClient(inner) => Pin::new(inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MultiStream::Tcp(inner) => Pin::new(inner).poll_flush(cx),
            MultiStream::TlsServer(inner) => Pin::new(inner).poll_flush(cx),
            MultiStream::TlsClient(inner) => Pin::new(inner).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MultiStream::Tcp(inner) => Pin::new(inner).poll_shutdown(cx),
            MultiStream::TlsServer(inner) => Pin::new(inner).poll_shutdown(cx),
            MultiStream::TlsClient(inner) => Pin::new(inner).poll_shutdown(cx),
        }
    }
}

#[derive(Debug)]
pub enum MultiIncoming {
    Tcp(TcpListener),
}

impl Stream for MultiIncoming {
    type Item = std::result::Result<(Multiaddr, MultiStream), io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            MultiIncoming::Tcp(inner) => match inner.poll_accept(cx)? {
                // Why can't get the peer address of the connected stream ?
                // Error will be "Transport endpoint is not connected",
                // so why incoming will appear unconnected stream ?
                Poll::Ready((stream, _)) => match stream.peer_addr() {
                    Ok(remote_address) => Poll::Ready(Some(Ok((
                        socketaddr_to_multiaddr(remote_address),
                        MultiStream::Tcp(stream),
                    )))),
                    Err(err) => {
                        debug!("stream get peer address error: {:?}", err);
                        Poll::Pending
                    }
                },
                Poll::Pending => Poll::Pending,
            },
        }
    }
}
