//! SMTP Server Transport.

use std::{io, mem};
use std::sync::Arc;
use abnf::EasyBuf;
use futures::{Async, AsyncSink, Future, Poll, StartSend};
use futures::sink::Sink;
use futures::stream::Stream;
use futures::sync::mpsc;
use native_tls::TlsAcceptor;
use tokio_core::io::{Io};
use tokio_tls::{AcceptAsync, TlsAcceptorExt, TlsStream};
use ::syntax::{Command, split_mail_data};
use super::service::{Data, Next, Reply, Request, RequestClass, Response};


/// A transport for the server side of an SMPT connection.
///
/// Because SMTP is a stateful protocol, that is, what should be happening
/// next depends on what happened recently, the transport is sequential: It
/// reads a request, waits for the response to it, processes that response,
/// and only then continues with the next request.
pub struct Transport<T: Io> {
    sock: Sock<T>,
    rd: EasyBuf,
    rdop: ReadOp,
    wrop: WriteOp,
}

impl<T: Io> Transport<T> {
    pub fn new(sock: T, acceptor: Arc<TlsAcceptor>) -> Self {
        Transport {
            sock: Sock::Clear(sock, acceptor),
            rd: EasyBuf::new(),
            rdop: ReadOp::Greeting,
            wrop: WriteOp::Wait(None),
        }
    }
}


//--- Stream and Sink

impl<T: Io> Stream for Transport<T> {
    type Item = Request;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if let Sock::Gone = self.sock {
            return Ok(Async::Ready(None));
        }
        if let Sock::Handshake(_) = self.sock {
            try_ready!(self.poll_handshake());
            // Handshake done; fall through to regular processing.
        }
        match self.rdop {
            ReadOp::Greeting => {
                self.rdop = ReadOp::Wait;
                Ok(Async::Ready(Some(Request::new(RequestClass::Greeting,
                                                  self.wrop.reply()))))
            }
            ReadOp::Wait => Ok(Async::NotReady),
            ReadOp::Command => self.read_command(),
            ReadOp::Data(_, None) => self.read_data(),
            ReadOp::Data(_, ref mut rx) => {
                let rx = rx.take().unwrap();
                Ok(Async::Ready(Some(Request::new(RequestClass::Data(rx),
                                                  self.wrop.reply()))))
            }
        }
    }
}


impl<T: Io> Sink for Transport<T> {
    type SinkItem = Response;
    type SinkError = io::Error;

    fn start_send(&mut self, item: Response) -> StartSend<Response, io::Error> {
        if let WriteOp::Write(_) = self.wrop {
            return Ok(AsyncSink::NotReady(item))
        }

        if item.next() == Next::PipelineCommand && self.rd.len() > 0 {
            self.wrop = WriteOp::Wait(Some(item.into_inner().0));
            self.rdop = ReadOp::Command
        }
        else {
            self.wrop = WriteOp::Write(item)
        }
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        // Handshake first because we need to mutably borrow self later.
        if let Sock::Handshake(_) = self.sock {
            try_ready!(self.poll_handshake());
            if let WriteOp::Write(_) = self.wrop {
                return Ok(Async::NotReady)
            }
            else {
                return Ok(Async::Ready(()))
            }
        }

        // Try writing if necessary. Return early if we don’t have a completed
        // response.
        if let WriteOp::Write(ref mut response) = self.wrop {
            match self.sock {
                Sock::Clear(ref mut sock, _) => {
                    try_ready!(Self::poll_write(sock, response.reply_mut()))
                }
                Sock::Handshake(_) => return Ok(Async::NotReady),
                Sock::Secure(ref mut sock) => {
                    try_ready!(Self::poll_write(sock, response.reply_mut()))
                }
                Sock::Gone => panic!("polling resolved transport")
            }
        }
        else {
            return Ok(Async::Ready(()))
        }

        // A response is complete, see what’s next.
        let (reply, next) = self.wrop.into_response().into_inner();
        self.wrop = WriteOp::Wait(Some(reply));
        match next {
            Next::Command | Next::PipelineCommand => {
                self.rdop = ReadOp::Command;
            }
            Next::Data => {
                let (tx, rx) = DataSender::pair();
                self.rdop = ReadOp::Data(tx, Some(rx));
            }
            Next::StartTls => self.start_tls(),
            Next::Quit => {
                self.sock = Sock::Gone;
            }
        }
        Ok(Async::Ready(()))
    }
}


impl<T: Io> Transport<T> {
    fn read_command(&mut self) -> Poll<Option<Request>, io::Error> {
        loop {
            match Command::parse(&mut self.rd) {
                Ok(Async::NotReady) => { }
                Ok(Async::Ready(command)) => {
                    self.rdop = ReadOp::Wait;
                    return Ok(Async::Ready(Some(
                        Request::new(RequestClass::Command(command),
                                     self.wrop.reply())
                    )))
                }
                Err(err) => {
                    self.rdop = ReadOp::Wait;
                    return Ok(Async::Ready(Some(
                        Request::new(RequestClass::CommandError(err),
                                     self.wrop.reply())
                    )))
                }
            }
            let eof = match self.sock {
                Sock::Clear(ref mut sock, _) => {
                    try_ready!(Self::poll_read(sock, &mut self.rd))
                }
                Sock::Secure(ref mut sock) => {
                    try_ready!(Self::poll_read(sock, &mut self.rd))
                }
                _ => panic!("read_command() on a socket not for reading") 
            };
            if eof {
                self.sock = Sock::Gone
            }
        }
    }

    fn read_data(&mut self) -> Poll<Option<Request>, io::Error> {
        {
            let tx = match self.rdop {
                ReadOp::Data(ref mut tx, _) => tx,
                _ =>  panic!("read_data() on wrong read op."),
            };
            loop {
                // XXX Perhaps even unwrap?
                try_ready!(tx.poll_complete());
                if self.rd.len() > 0 {
                    if let Some(data) = split_mail_data(&mut self.rd) {
                        if let AsyncSink::NotReady(data)
                                                  = tx.start_send(Ok(data))? {
                            // Feck. Set’s put it all back together and
                            // pretend it never happend.
                            let mut data = data.unwrap();
                            data.get_mut().extend_from_slice(
                                                          self.rd.as_slice());
                            self.rd = data;
                            return Ok(Async::NotReady)
                        }
                        // Break so we can change self.rdop (which is
                        // currently borrowed) to ReadOp::Wait
                        break;
                    }
                    else {
                        let buf = self.rd.clone();
                        if let AsyncSink::NotReady(_)
                                                   = tx.start_send(Ok(buf))? {
                            return Ok(Async::NotReady)
                        }
                        self.rd = EasyBuf::new();
                    }
                }
                let eof = match self.sock {
                    Sock::Clear(ref mut sock, _) => {
                        try_ready!(Self::poll_read(sock, &mut self.rd))
                    }
                    Sock::Secure(ref mut sock) => {
                        try_ready!(Self::poll_read(sock, &mut self.rd))
                    }
                    _ => panic!("read_command() on a socket not for reading") 
                };
                if eof {
                    self.sock = Sock::Gone
                }
            }
        }
        self.rdop = ReadOp::Wait;
        Ok(Async::NotReady)
    }

    fn poll_read<S: io::Read>(mut sock: S, buf: &mut EasyBuf)
                              -> Poll<bool, io::Error> {
        let mut buf = buf.get_mut();
        let before = buf.len();
        match sock.read_to_end(&mut buf) {
            Ok(_) => Ok(Async::Ready(true)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                if buf.len() == before {
                    Ok(Async::NotReady)
                }
                else {
                    Ok(Async::Ready(false))
                }
            }
            Err(e) => Err(e)
        }
    }

    fn poll_write<S: io::Write>(mut sock: S, reply: &mut Reply)
                                -> Poll<(), io::Error> {
        while !reply.is_empty() {
            let n = try_nb!(sock.write(reply.as_slice()));
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero,
                                          "failed to write to transport"));
            }
            reply.as_vec_mut().drain(..n);
        }

        try_nb!(sock.flush());
        Ok(Async::Ready(()))
    }

    fn poll_handshake(&mut self) -> Poll<(), io::Error> {
        let secure = match self.sock {
            Sock::Handshake(ref mut accept) => {
                try_ready!(
                    accept.poll()
                          .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                )
            }
            _ => return Ok(Async::NotReady)
        };
        self.sock = Sock::Secure(secure);
        Ok(Async::Ready(()))
    }

    fn start_tls(&mut self) {
        let (sock, accept) = match mem::replace(&mut self.sock, Sock::Gone) {
            Sock::Clear(sock, accept) => (sock, accept),
            _ => panic!("called start_tls on a non-clear socket")
        };
        self.sock = Sock::Handshake(accept.accept_async(sock));
    }
}


//------------ Sock ----------------------------------------------------------

enum Sock<T> {
    /// The socket is in clear-text mode.
    Clear(T, Arc<TlsAcceptor>),

    /// The socket is currently in the process of a TLS handshake.
    ///
    /// If the handshake succeeds, the socket will proceed to `Secure` and
    /// reading continues with a `Command` operation. Should the handshake
    /// fail, the transport will terminate and proceed to `Gone`.
    Handshake(AcceptAsync<T>),

    /// The socket is in encrypted mode.
    Secure(TlsStream<T>),

    /// The socket is unusable.
    Gone,
}


//------------ ReadOp --------------------------------------------------------

enum ReadOp {
    /// Request a greeting.
    Greeting,

    /// Don’t read, wait for a response before continuing.
    Wait,

    /// Read and dispatch an SMTP command.
    Command,

    /// Read and dispatch mail data.
    ///
    /// This means to keep reading from the socket until the end of mail data
    /// indication and dispatch it into the sender.
    Data(DataSender, Option<Data>),
}


//------------ WriteOp -------------------------------------------------------

enum WriteOp {
    /// Nothing to write right now.
    ///
    /// If the inner value is not `None`, it should be included into the next
    /// request.
    Wait(Option<Reply>),

    /// Write the complete reply in the response, then do what next demands.
    Write(Response),
}

impl WriteOp {
    fn into_response(&mut self) -> Response {
        let res = mem::replace(self, WriteOp::Wait(None));
        if let WriteOp::Write(response) = res {
            response
        }
        else {
            panic!("Writeop::into_response() called for a WriteOp::Wait")
        }
    }

    fn reply(&mut self) -> Reply {
        match *self {
            WriteOp::Wait(ref mut reply) => {
                reply.take().unwrap_or_else(Reply::new)
            }
            WriteOp::Write(_) => Reply::new()
        }
    }
}


//------------ DataSender ----------------------------------------------------

/// Where to send data chunks to.
///
/// This is a light wrapper around the actual channel that sends the chunks.
/// The only thing it does is swallow any errors from the channel. The only
/// error that can happen is that the receiving end is dropped. We assume that
/// in this case the consumer doesn’t care about any further data and pretend
/// that it was successfully sent by returning ‘ready’ to everything.
struct DataSender(Option<mpsc::Sender<Result<EasyBuf, io::Error>>>);

impl DataSender {
    fn pair() -> (Self, Data) {
        let (tx, rx) = Data::pair();
        (DataSender(Some(tx)), rx)
    }
}

impl Sink for DataSender {
    type SinkItem = Result<EasyBuf, io::Error>;
    type SinkError = io::Error;

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        match self.0 {
            Some(ref mut tx) => {
                if let Ok(some) = tx.poll_complete() {
                    return Ok(some)
                }
            }
            None => return Ok(Async::Ready(()))
        }
        self.0 = None;
        Ok(Async::Ready(()))
    }

    fn start_send(&mut self, item: Self::SinkItem)
                  -> StartSend<Self::SinkItem, Self::SinkError> {
        match self.0 {
            Some(ref mut tx) => {
                if let Ok(some) = tx.start_send(item) {
                    return Ok(some)
                }
            }
            None => return Ok(AsyncSink::Ready)
        }
        self.0 = None;
        Ok(AsyncSink::Ready)
    }
}
