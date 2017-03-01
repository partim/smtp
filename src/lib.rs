//! SMTP: Simple Mail Transfer Protocol
//!
//! This implementation supports the following extensions:
//!
//! * EXPN (defines the verb EXPN, see RFC 5321)
//! * HELP (defines the verb HELP, see RFC 5321)
//! * 8BITMIME (defines the mail-parameter BODY, see RFC 6152)
//! * SIZE (defines the mail-parameter SIZE, see RFC 1870)
//! * PIPELINING (RFC 2920)
//! * DSN (defines the RET and ENVID mail-parameters and the NOTIFY and ORCPT
//!   rctp-parameters, see RFC 3461)
//! * ETRN (RFC 1985)
//! * ENHANCEDSTATUSCODES (RFC 2034)
//! * STARTTLS (defines the STARTTLS verb, see RFC 3207)
//! * AUTH (defines the AUTH verb and the AUTH mail-parameter, see RFC 4954)
//! * SMTPUTF8 (defines the mail-parameter SMTPUTF8, see RFC 6531)
//!
//! This implementation may later support these extensions:
//!
//! * BINARYMIME (see RFC 3030)
//! * CHUNKING (see RFC 3030)
//! * DELIVERBY (see RFC 2852)
//! * BURL (see RFC 4468)
//! * FUTURERELEASE (see RFC 4865)

#[macro_use] extern crate abnf;
#[macro_use] extern crate futures;
#[macro_use] extern crate log;
extern crate native_tls;
#[macro_use] extern crate tokio_core;
extern crate tokio_proto;
extern crate tokio_service;
extern crate tokio_tls;

pub mod server;
pub mod syntax;

/// A marker used to flag protocols as being for SMTP.
pub struct Smtp;


