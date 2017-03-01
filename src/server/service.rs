//! Components for making an SMTP service.

use std::io;
use std::net::SocketAddr;
use futures::future::Future;
use tokio_core::io::EasyBuf;
use tokio_proto::streaming::Body;
use ::syntax::{Command, CommandError};


//============ Service and NewService ========================================

pub trait Service {
    type Future: Future<Item=Response, Error=io::Error>;

    fn call(&self, req: Request) -> Self::Future;
}

pub trait NewService {
    type Instance: Service;

    fn new_service(&self, peer: SocketAddr, secure: bool)
                   -> io::Result<Self::Instance>;
}


//============ Request =======================================================

/// An incoming SMTP request.
#[derive(Debug)]
pub struct Request {
    /// The kind of request this is.
    class: RequestClass,

    /// Where to append the reply into.
    reply: Reply,
}

impl Request {
    pub fn new(class: RequestClass, reply: Reply) -> Self {
        Request{class: class, reply: reply}
    }

    pub fn class(&self) -> &RequestClass {
        &self.class
    }

    pub fn reply(&self) -> &Reply {
        &self.reply
    }

    pub fn reply_mut(&mut self) -> &mut Reply {
        &mut self.reply
    }

    pub fn into_response(self, next: Next) -> Response {
        Response::new(self.reply, next)
    }
}


//------------ RequestClass --------------------------------------------------

#[derive(Debug)]
pub enum RequestClass {
    /// Request for the greeting at the beginning of the exchange.
    Greeting,

    /// A regular command.
    Command(Command),

    /// Mail data.
    Data(Data),

    /// An error happened parsing a command.
    ///
    /// This is only for errors where the end of the command could be
    /// successfully parsed and we can continue afterwards. If things get
    /// too wonky, the transport will just drop.
    CommandError(CommandError),
}


//============ Response ======================================================

/// An outgoing SMTP response.
#[derive(Clone, Debug)]
pub struct Response {
    /// The reply to send to the client.
    reply: Reply,

    /// What to do next.
    next: Next,
}

impl Response {
    pub fn new(reply: Reply, next: Next) -> Self {
        Response{reply: reply, next: next}
    }

    pub fn reply(&self) -> &Reply {
        &self.reply
    }

    pub fn reply_mut(&mut self) -> &mut Reply {
        &mut self.reply
    }

    pub fn next(&self) -> Next {
        self.next
    }

    pub fn set_next(&mut self, next: Next) {
        self.next = next
    }

    pub fn into_inner(self) -> (Reply, Next) {
        (self.reply, self.next)
    }
}


//------------ Next ----------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Next {
    /// A command is next.
    ///
    /// Send out all aggregated replies, then process a command.
    Command,

    /// A pipelineable command is next.
    ///
    /// If the read buffer is empty, send out all aggregated replies. Then
    /// process a command.
    PipelineCommand,

    /// Mail data is next.
    ///
    /// Send out all aggregated replies, then process mail data.
    Data,

    /// Switch to TLS.
    ///
    /// Send out all aggregated replies. Drop the current service. Start a
    /// TLS handshake. If this succeeds, create a new service and start
    /// processing. If the handshake fails, close the connection.
    StartTls,

    /// Quit.
    ///
    /// Send out all aggregated replies then close the connection and drop
    /// the current service.
    Quit,
}


//============ Reply =========================================================

#[derive(Clone, Debug)]
pub struct Reply {
    buf: Vec<u8>,
}

impl Reply {
    pub fn new() -> Reply {
        Reply { buf: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn as_vec_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }
}


//============ Data and DataSender ===========================================

pub type Data = Body<EasyBuf, io::Error>;
