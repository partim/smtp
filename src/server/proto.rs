//! SMTP Protocols.

use std::{io, mem};
use std::marker::PhantomData;
use std::sync::Arc;
use native_tls::TlsAcceptor;
use futures::{Async, AsyncSink, Future, Poll, Sink, Stream};
use tokio_core::reactor;
use tokio_core::io::Io;
use tokio_proto::BindServer;
use tokio_service::Service;
use ::Smtp;
use super::service::{Request, Response};
use super::transport::Transport;


pub struct ServerProto<T: 'static> {
    acceptor: Arc<TlsAcceptor>,
    marker: PhantomData<T>,
}

impl<T: Io + 'static> BindServer<Smtp, T> for ServerProto<T> {
    type ServiceRequest = Request;
    type ServiceResponse = Response;
    type ServiceError = io::Error;

    fn bind_server<S>(&self, handle: &reactor::Handle, io: T, service: S)
                   where S: Service<Request=Self::ServiceRequest,
                                    Response=Self::ServiceResponse,
                                    Error=Self::ServiceError> + 'static {
        handle.spawn(Dispatch::new(service, io, self.acceptor.clone()))
    }
}


pub struct Dispatch<S: Service, T: Io + 'static> {
    service: S,
    transport: Transport<T>,
    pending: Pending<S::Future>,
}

impl<S: Service, T: Io + 'static> Dispatch<S, T> {
    fn new(service: S, io: T, acceptor: Arc<TlsAcceptor>) -> Self {
        Dispatch {
            service: service,
            transport: Transport::new(io, acceptor),
            pending: Pending::Empty,
        }
    }
}


//--- Future

impl<S,T> Future for Dispatch<S, T>
     where S: Service<Request=Request, Response=Response, Error=io::Error>,
           T: Io + 'static {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<(), ()> {
        loop {
            try_ready!(self.poll_active());
            try_ready!(self.poll_done());
            try_ready!(self.poll_sinking());
            if try_ready!(self.poll_request()).is_none() {
                return Ok(Async::NotReady)
            }
        }
    }
}

impl<S,T> Dispatch<S, T>
     where S: Service<Request=Request, Response=Response, Error=io::Error>,
           T: Io + 'static {
    /// Polls an active future.
    ///
    /// Returns ready if polling should continue or non-ready if polling
    /// should stop non-ready right away.
    fn poll_active(&mut self) -> Poll<(), ()> {
        let result = match self.pending {
            Pending::Active(ref mut fut) => try_result!(fut.poll()),
            _ => return Ok(Async::Ready(()))
        };
        self.pending = Pending::Done(result);
        Ok(Async::Ready(()))
    }

    /// Polls a done future.
    ///
    /// Returns ready if polling should continue or non-ready if polling
    /// should stop non-ready right away.
    fn poll_done(&mut self) -> Poll<(), ()> {
        match self.pending {
            Pending::Done(_) => { }
            _ => return Ok(Async::Ready(()))
        }
        let result = match mem::replace(&mut self.pending, Pending::Sinking) {
            Pending::Done(result) => result,
            _ => panic!()
        };
        let response = match result {
            Ok(response) => response,
            Err(err) => {
                error!("Service error: {}", err);
                return Err(())
            }
        };
        self.pending = match self.transport.start_send(response) {
            Ok(AsyncSink::Ready) => return Ok(Async::Ready(())),
            Ok(AsyncSink::NotReady(response)) => Pending::Done(Ok(response)),
            Err(_) => return Err(()), // XXX Hmpf.
        };
        Ok(Async::NotReady)
    }

    fn poll_sinking(&mut self) -> Poll<(), ()> {
        if let Pending::Sinking = self.pending {
            self.transport.poll_complete().map_err(|_| ())
        }
        else {
            Ok(Async::Ready(()))
        }
    }

    fn poll_request(&mut self) -> Poll<Option<()>, ()> {
        if let Pending::Empty = self.pending {
            match try_ready!(self.transport.poll().map_err(|_| ())) {
                Some(request) => {
                    self.pending = Pending::Active(self.service.call(request));
                    Ok(Async::Ready(Some(())))
                }
                None => Ok(Async::Ready(None))
            }
        }
        else {
            Ok(Async::Ready(Some(())))
        }
    }
}

enum Pending<F: Future> {
    Empty,
    Active(F),
    Done(Result<F::Item, F::Error>),
    Sinking,
}

