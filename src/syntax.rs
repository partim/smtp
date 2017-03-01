
use std::fmt;
use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};
use abnf::core;
use abnf::{Async, EasyBuf, Poll};
use abnf::ipaddr::{parse_ipv4_addr, parse_ipv6_addr};
use abnf::parse::{rule, token};
use abnf::parse::token::{TokenError, Token};


//============ Command and Reply =============================================

//------------ Command ------------------------------------------------------

/// SMTP Command
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    // RFC 5321
    Ehlo(MailboxDomain),
    Helo(Domain),
    Mail(ReversePath, MailParameters),
    Rcpt(RcptPath, RcptParameters),
    Data,
    Rset,
    Vrfy(Word, VrfyParameters),
    Expn(Word, ExpnParameters),
    Help(Option<Word>),
    Noop,
    Quit,

    // RFC 3207
    StartTls,

    // RFC 4954
    Auth(AuthArgs),
}

impl Command {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_fail!(Self::parse_ehlo(buf));
        try_fail!(Self::parse_helo(buf));
        try_fail!(Self::parse_mail(buf));
        try_fail!(Self::parse_rcpt(buf));
        try_fail!(Self::parse_data(buf));
        try_fail!(Self::parse_rset(buf));
        try_fail!(Self::parse_vrfy(buf));
        try_fail!(Self::parse_expn(buf));
        try_fail!(Self::parse_help(buf));
        try_fail!(Self::parse_noop(buf));
        try_fail!(Self::parse_quit(buf));
        try_fail!(Self::parse_starttls(buf));
        try_fail!(Self::parse_auth(buf));
        Err(CommandError)
    }


    fn parse_ehlo(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(token::skip_literal(buf, b"EHLO"));
        try_ready!(core::skip_wsps(buf));
        let domain = try_ready!(MailboxDomain::parse(buf));
        try_ready!(core::skip_opt_wsps(buf));
        try_ready!(core::skip_crlf(buf));
        Ok(Async::Ready(Command::Ehlo(domain)))
    }

    fn parse_helo(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(token::skip_literal(buf, b"HELO"));
        try_ready!(core::skip_wsps(buf));
        let domain = try_ready!(Domain::parse(buf));
        try_ready!(core::skip_opt_wsps(buf));
        try_ready!(core::skip_crlf(buf));
        Ok(Async::Ready(Command::Helo(domain)))
    }

    fn parse_mail(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(token::skip_literal(buf, b"MAIL"));
        try_ready!(core::skip_wsps(buf));
        try_ready!(token::skip_literal(buf, b"FROM:"));
        try_ready!(core::skip_opt_wsps(buf));
        let path = try_ready!(ReversePath::parse(buf));
        let mut params = MailParameters::default();
        while try_ready!(core::skip_opt_wsps(buf)) {
            if try_result!(params.parse_one(buf)).is_err() {
                break
            }
        }
        try_ready!(core::skip_crlf(buf));
        Ok(Async::Ready(Command::Mail(path, params)))
    }

    fn parse_rcpt(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(token::skip_literal(buf, b"RCPT"));
        try_ready!(core::skip_wsps(buf));
        try_ready!(token::skip_literal(buf, b"TO:"));
        try_ready!(core::skip_opt_wsps(buf));
        let path = try_ready!(RcptPath::parse(buf));
        let mut params = RcptParameters::default();
        while try_ready!(core::skip_opt_wsps(buf)) {
            if try_result!(params.parse_one(buf)).is_err() {
                break
            }
        }
        try_ready!(core::skip_crlf(buf));
        Ok(Async::Ready(Command::Rcpt(path, params)))
    }

    fn parse_data(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(token::skip_literal(buf, b"DATA"));
        try_ready!(core::skip_opt_wsps(buf));
        try_ready!(core::skip_crlf(buf));
        Ok(Async::Ready(Command::Data))
    }

    fn parse_rset(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(token::skip_literal(buf, b"RSET"));
        try_ready!(core::skip_opt_wsps(buf));
        try_ready!(core::skip_crlf(buf));
        Ok(Async::Ready(Command::Rset))
    }

    fn parse_vrfy(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(token::skip_literal(buf, b"VRFY"));
        try_ready!(core::skip_wsps(buf));
        let word = try_ready!(Word::parse(buf));
        let mut params = VrfyParameters::default();
        while try_ready!(core::skip_opt_wsps(buf)) {
            if try_result!(params.parse_one(buf)).is_err() {
                break
            }
        }
        try_ready!(core::skip_crlf(buf));
        Ok(Async::Ready(Command::Vrfy(word, params)))
    }

    fn parse_expn(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(token::skip_literal(buf, b"EXPN"));
        try_ready!(core::skip_wsps(buf));
        let word = try_ready!(Word::parse(buf));
        let mut params = ExpnParameters::default();
        while try_ready!(core::skip_opt_wsps(buf)) {
            if try_result!(params.parse_one(buf)).is_err() {
                break
            }
        }
        try_ready!(core::skip_crlf(buf));
        Ok(Async::Ready(Command::Expn(word, params)))
    }

    fn parse_help(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(token::skip_literal(buf, b"EXPN"));
        try_ready!(core::skip_wsps(buf));
        let word = try_result!(Word::parse(buf)).ok();
        try_ready!(core::skip_opt_wsps(buf));
        try_ready!(core::skip_crlf(buf));
        Ok(Async::Ready(Command::Help(word)))
    }

    fn parse_noop(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(token::skip_literal(buf, b"NOOP"));
        try_ready!(core::skip_opt_wsps(buf));
        try_ready!(core::skip_crlf(buf));
        Ok(Async::Ready(Command::Noop))
    }

    fn parse_quit(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(token::skip_literal(buf, b"QUIT"));
        try_ready!(core::skip_opt_wsps(buf));
        try_ready!(core::skip_crlf(buf));
        Ok(Async::Ready(Command::Quit))
    }

    fn parse_starttls(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(token::skip_literal(buf, b"STARTTLS"));
        try_ready!(core::skip_opt_wsps(buf));
        try_ready!(core::skip_crlf(buf));
        Ok(Async::Ready(Command::StartTls))
    }

    fn parse_auth(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(token::skip_literal(buf, b"AUTH"));
        let args = try_ready!(AuthArgs::parse(buf));
        try_ready!(core::skip_opt_wsps(buf));
        try_ready!(core::skip_crlf(buf));
        Ok(Async::Ready(Command::Auth(args)))
    }
}


//============ Command Parameters ============================================


//------------ AuthArgs -----------------------------------------------------

/// The arguments of an AUTH command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthArgs {
    pub mechanism: EasyBuf,
    pub initial: Option<EasyBuf>,
}

/// # Parsing and Composing
///
/// We parse the auth arguments as if they were defined like so:
///
/// ```text
/// auth-arguments   = SP sasl-mech [SP initial-response]
///
/// sasl-mech        = atom
///
/// initial-response = atom
/// ```
///
/// Both `sasl-mech` and `initial-response` are more restricted, but we can
/// leave it to any SASL processor to sort this out.
impl AuthArgs {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, CommandError> {
        try_ready!(core::skip_wsps(buf));
        let mechanism = try_ready!(parse_atom(buf));
        let initial = try_result!(rule::group(buf, |buf| {
            try_ready!(core::skip_wsps(buf));
            parse_atom(buf)
        })).ok();
        Ok(Async::Ready(AuthArgs{mechanism: mechanism, initial: initial}))
    }
}


//------------ ExpnParameters -----------------------------------------------

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExpnParameters {
    pub smtputf8: Option<()>,
}

impl ExpnParameters {
    pub fn parse_one(&mut self, buf: &mut EasyBuf) -> Poll<(), TokenError> {
        try_ready!(token::skip_literal(buf, b"SMTPUTF8"));
        self.smtputf8 = Some(());
        Ok(Async::Ready(()))
    }
}


//------------ MailParameters -----------------------------------------------

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MailParameters {
    pub body: Option<BodyValue>,
    pub size: Option<u64>,
    pub ret: Option<RetValue>,
    pub envid: Option<Xtext>,
    pub auth: Option<Mailbox>,
    pub smtputf8: Option<()>,
}

impl MailParameters {
    pub fn new() -> Self {
        MailParameters::default()
    }
}

impl MailParameters {
    pub fn parse_one(&mut self, buf: &mut EasyBuf) -> Poll<(), TokenError> {
        try_fail!(self.parse_body(buf));
        try_fail!(self.parse_size(buf));
        try_fail!(self.parse_ret(buf));
        try_fail!(self.parse_envid(buf));
        try_fail!(self.parse_auth(buf));
        try_fail!(self.parse_smtputf8(buf));
        Err(TokenError)
    }

    /// Parses the mail-parameter BODY.
    ///
    /// # Definition
    ///
    /// ```text
    /// body-mail-parameter = "BODY=" body-value
    ///
    /// body-value          = "7BIT" / "8BITMIME" / "BINARYMIME"
    /// ```
    ///
    /// Defined in RFC 6152 and extended in RFC 3030.
    fn parse_body(&mut self, buf: &mut EasyBuf) -> Poll<(), CommandError> {
        rule::group(buf, |buf| {
            try_ready!(token::skip_literal(buf, b"BODY="));
            self.body = Some(try_ready!(BodyValue::parse(buf)));
            Ok(Async::Ready(()))
        })
    }

    /// Parses the mail-parameter SIZE.
    ///
    /// # Definition
    ///
    /// ```text
    /// size-mail-parameter = "SIZE=" size-value
    ///
    /// size-value          = 1*20DIGIT
    /// ```
    ///
    /// Defined in RFC 1870.
    fn parse_size(&mut self, buf: &mut EasyBuf) -> Poll<(), CommandError> {
        rule::group(buf, |buf| {
            try_ready!(token::skip_literal(buf, b"SIZE="));
            self.size = Some(try_ready!(core::u64_digits(buf)));
            Ok(Async::Ready(()))
        })
    }

    /// Parses the mail-parameter RET.
    ///
    /// # Definition
    ///
    /// ```text
    /// ret-mail-parameter = "RET=" ret-value
    ///
    /// ret-value          = "FULL" / "HDRS"
    /// ```
    ///
    /// Defined in RFC 3461, section 4.3.
    fn parse_ret(&mut self, buf: &mut EasyBuf) -> Poll<(), TokenError> {
        rule::group(buf, |buf| {
            try_ready!(token::skip_literal(buf, b"RET="));
            self.ret = Some(try_ready!(RetValue::parse(buf)));
            Ok(Async::Ready(()))
        })
    }

    /// Parses the mail-parameter ENVID.
    ///
    /// # Definition
    ///
    /// ```text
    /// envid-parameter = "ENVID=" xtext
    /// ```
    ///
    /// Defined in RFC 3461, section 4.4.
    fn parse_envid(&mut self, buf: &mut EasyBuf) -> Poll<(), TokenError> {
        rule::group(buf, |buf| {
            try_ready!(token::skip_literal(buf, b"ENVID="));
            self.envid = Some(try_ready!(Xtext::parse(buf)));
            Ok(Async::Ready(()))
        })
    }

    /// Parses the mail-parameter AUTH.
    ///
    /// # Definition
    ///
    /// ```text
    /// auth-mail-parameter = "AUTH=" Mailbox
    /// ```
    ///
    /// Defined in RFC 4954, section 5.
    fn parse_auth(&mut self, buf: &mut EasyBuf) -> Poll<(), CommandError> {
        rule::group(buf, |buf| {
            try_ready!(token::skip_literal(buf, b"AUTH="));
            self.auth = Some(try_ready!(Mailbox::parse(buf)));
            Ok(Async::Ready(()))
        })
    }

    /// Parses the mail-parameter SMTPUTF8.
    ///
    /// Defined in RFC 6531.
    fn parse_smtputf8(&mut self, buf: &mut EasyBuf) -> Poll<(), TokenError> {
        rule::group(buf, |buf| {
            try_ready!(token::skip_literal(buf, b"SMTPUTF8"));
            self.smtputf8 = Some(());
            Ok(Async::Ready(()))
        })
    }
}


//------------ RcptParameters -----------------------------------------------

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RcptParameters {
    pub notify: Option<NotifyValue>,
    pub orcpt: Option<OrcptParameter>,
}

impl RcptParameters {
    pub fn parse_one(&mut self, buf: &mut EasyBuf) -> Poll<(), TokenError> {
        try_fail!(self.parse_notify(buf));
        try_fail!(self.parse_orcpt(buf));
        Err(TokenError)
    }

    fn parse_notify(&mut self, buf: &mut EasyBuf) -> Poll<(), TokenError> {
        rule::group(buf, |buf| {
            try_ready!(token::skip_literal(buf, b"NOTIFY="));
            self.notify = Some(try_ready!(NotifyValue::parse(buf)));
            Ok(Async::Ready(()))
        })
    }

    fn parse_orcpt(&mut self, buf: &mut EasyBuf) -> Poll<(), TokenError> {
        rule::group(buf, |buf| {
            try_ready!(token::skip_literal(buf, b"ORCPT="));
            self.orcpt = Some(try_ready!(OrcptParameter::parse(buf)));
            Ok(Async::Ready(()))
        })
    }
}


//------------ VrfyParameters ------------------------------------------------

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VrfyParameters {
    pub smtputf8: Option<()>
}

impl VrfyParameters {
    pub fn parse_one(&mut self, buf: &mut EasyBuf) -> Poll<(), TokenError> {
        try_ready!(token::skip_literal(buf, b"SMTPUTF8"));
        self.smtputf8 = Some(());
        Ok(Async::Ready(()))
    }
}


//============ Components ====================================================


//------------ AddressLiteral ------------------------------------------------

/// A literal IP address.
///
/// # Definition
///
/// ```text
///   address-literal  = "[" ( IPv4-address-literal /
///                    IPv6-address-literal /
///                    General-address-literal ) "]"
///
///   IPv4-address-literal  = Snum 3("."  Snum)
///
///   IPv6-address-literal  = "IPv6:" IPv6-addr
///
///   General-address-literal  = Standardized-tag ":" 1*dcontent
///
///   Standardized-tag  = Ldh-str
///
///   dcontent       = %d33-90 / ; Printable US-ASCII
///                  %d94-126 ; excl. "[", "\", "]"
/// ```
///
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddressLiteral {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    General {
        tag: EasyBuf,
        content: EasyBuf,
    }
}

impl AddressLiteral {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        rule::group(buf, |buf| {
            try_ready!(token::skip_octet(buf, b'['));
            let res = try_ready!(Self::parse_inner(buf));
            try_ready!(token::skip_octet(buf, b']'));
            Ok(Async::Ready(res))
        })
    }

    fn parse_inner(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        try_fail!(Self::parse_ipv4(buf));
        try_fail!(Self::parse_ipv6(buf));
        try_fail!(Self::parse_general(buf));
        Err(TokenError)
    }

    fn parse_ipv4(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        Ok(Async::Ready(
                AddressLiteral::Ipv4(try_ready!(parse_ipv4_addr(buf)))))
    }

    fn parse_ipv6(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        rule::group(buf, |buf| {
            try_ready!(token::skip_literal(buf, b"IPv6:"));
            Ok(Async::Ready(
                    AddressLiteral::Ipv6(try_ready!(parse_ipv6_addr(buf)))))
        })
    }

    fn parse_general(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        rule::group(buf, |buf| {
            let tag = try_ready!(parse_ldh_str(buf));
            try_ready!(token::skip_octet(buf, b':'));
            let content = try_ready!(parse_dcontents(buf));
            Ok(Async::Ready(AddressLiteral::General{tag: tag,
                                                    content: content}))
        })
    }
}

impl fmt::Display for AddressLiteral {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AddressLiteral::Ipv4(ref addr) => {
                write!(f, "[{}]", addr)
            }
            AddressLiteral::Ipv6(ref addr) => {
                write!(f, "[IPv6:{}]", addr)
            }
            AddressLiteral::General{ref tag, ref content} => {
                write!(f, "[{}:{}]",
                       String::from_utf8_lossy(tag.as_slice()),
                       String::from_utf8_lossy(content.as_slice()))
            }
        }
    }
}


//------------ BodyValue ----------------------------------------------------

/// The BODY parameter to the ESMTP MAIL command
///
/// See RFC 6152, section 2, and RFC 3030, section 3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyValue {
    SevenBit,
    EightBitMime,
    BinaryMime,
}

impl BodyValue {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        try_fail!(token::translate_literal(buf, b"7BIT",
                                           BodyValue::SevenBit));
        try_fail!(token::translate_literal(buf, b"8BITMIME",
                                           BodyValue::EightBitMime));
        try_fail!(token::translate_literal(buf, b"BINARYMIME",
                                           BodyValue::BinaryMime));
        Err(TokenError)
    }
}


//------------ Domain -------------------------------------------------------

/// A domain.
///
/// # Definition
///
/// ```text
/// Domain         = sub-domain *("." sub-domain)
///
/// sub-domain     = Let-dig [Ldh-str]
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Domain(EasyBuf);

impl Domain {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        Ok(Async::Ready(Domain(try_ready!(token::parse(buf, Self::token)))))
    }

    pub fn skip(buf: &mut EasyBuf) -> Poll<(), TokenError> {
        token::skip(buf, Self::token)
    }

    fn token(token: &mut Token) -> Poll<(), TokenError> {
        try_ready!(sub_domain(token));
        while try_ready!(token::opt_octet(token, b'.')) {
            try_ready!(sub_domain(token));
        }
        Ok(Async::Ready(()))
    }
}


//------------ DsnAddressType -----------------------------------------------

/// DSN Address Types
///
/// See https://www.iana.org/assignments/dsn-types/dsn-types.xhtml#dsn-types-1
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DsnAddressType {
    Rfc822,
    X400,
    Utf8
}

impl DsnAddressType {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        try_fail!(token::translate_literal(buf, b"rfc822",
                                           DsnAddressType::Rfc822));
        try_fail!(token::translate_literal(buf, b"x400",
                                           DsnAddressType::X400));
        try_fail!(token::translate_literal(buf, b"utf-8",
                                           DsnAddressType::Utf8));
        Err(TokenError)
    }
}


//------------ LocalPart ----------------------------------------------------

/// The local part of a mailbox.
///
/// # Definition
///
/// ```text
/// Local-part     = Dot-string / Quoted-string
///                ; MAY be case-sensitive
///
/// Dot-string     = Atom *("."  Atom)
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalPart {
    Dotted(EasyBuf),
    Quoted(QuotedString)
}

impl LocalPart {
    pub fn decode(&self) -> Cow<[u8]> {
        match *self {
            LocalPart::Dotted(ref buf) => Cow::Borrowed(buf.as_slice()),
            LocalPart::Quoted(ref quoted) => quoted.decode(),
        }
    }
}

impl LocalPart {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        try_fail!(Self::parse_dotted(buf));
        try_fail!(Self::parse_quoted(buf));
        Err(TokenError)
    }

    fn parse_dotted(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        let res = try_ready!(token::parse(buf, |token| {
            try_ready!(atom(token));
            while try_ready!(token::opt_octet(token, b'.')) {
                try_ready!(atom(token))
            }
            Ok(Async::Ready(()))
        }));
        Ok(Async::Ready(LocalPart::Dotted(res)))
    }

    fn parse_quoted(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        Ok(Async::Ready(
                LocalPart::Quoted(try_ready!(QuotedString::parse(buf)))))
    }
}


//------------ Mailbox -------------------------------------------------------

/// A mailbox.
///
/// # Definition
///
/// ```text
/// Mailbox        = Local-part "@" Mailbox-domain
/// ```
///
/// Note: `Mailbox-domain` is not part of the RFC but has been defined since
/// we can’t embed enums.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mailbox {
    local: LocalPart,
    domain: MailboxDomain,
}

impl Mailbox {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        rule::group(buf, |buf| {
            let local = try_ready!(LocalPart::parse(buf));
            try_ready!(token::skip_octet(buf, b'@'));
            let domain = try_ready!(MailboxDomain::parse(buf));
            Ok(Async::Ready(Mailbox{local: local, domain: domain}))
        })
    }
}


//------------ MailboxDomain ------------------------------------------------

/// The domain part of a mailbox.
///
///
/// # Definition
///
///
/// This is not a type defined in the RFC. If it were, it would be defined
/// as follows:
///
/// ```text
/// Mailbox-domain = ( Domain / address-literal )
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MailboxDomain {
    Domain(Domain),
    Address(AddressLiteral)
}

impl MailboxDomain {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        try_fail!(Self::parse_domain(buf));
        try_fail!(Self::parse_address(buf));
        Err(TokenError)
    }

    fn parse_domain(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        Ok(Async::Ready(MailboxDomain::Domain(
            try_ready!(Domain::parse(buf))
        )))
    }

    fn parse_address(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        Ok(Async::Ready(MailboxDomain::Address(
            try_ready!(AddressLiteral::parse(buf))
        )))
    }
}

impl From<Domain> for MailboxDomain {
    fn from(domain: Domain) -> MailboxDomain {
        MailboxDomain::Domain(domain)
    }
}


//------------ NotifyValue --------------------------------------------------

/// The NOTIFY parameter of the ESMTP RCPT command
///
/// # Definition
///
/// ```text
/// notify-esmtp-value    = "NEVER" / (notify-list-element
///                                    *( "," notify-list-element))
///
/// notify-list-element   = "SUCCESS" / "FAILURE" / "DELAY"
/// ```
///
/// See RFC 3461, section 4.1.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NotifyValue {
    pub success: bool,
    pub failure: bool,
    pub delay: bool
}

impl NotifyValue {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        try_fail!(token::translate_literal(buf, b"NEVER",
                                           NotifyValue::default()));
        try_fail!(Self::parse_list(buf));
        Err(TokenError)
    }

    fn parse_list(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        let mut res = NotifyValue::default();
        try_ready!(Self::parse_value(buf, &mut res));
        while try_ready!(token::skip_opt_octet(buf, b',')) {
            try_ready!(Self::parse_value(buf, &mut res))
        }
        Ok(Async::Ready(res))
    }

    fn parse_value(buf: &mut EasyBuf, res: &mut Self)
                   -> Poll<(), TokenError> {
        if try_result!(token::skip_literal(buf, b"SUCCESS")).is_ok() {
            res.success = true;
            return Ok(Async::Ready(()))
        }
        if try_result!(token::skip_literal(buf, b"FAILURE")).is_ok() {
            res.failure = true;
            return Ok(Async::Ready(()))
        }
        if try_result!(token::skip_literal(buf, b"DELAY")).is_ok() {
            res.delay = true;
            return Ok(Async::Ready(()))
        }
        Err(TokenError)
    }
}


//------------ OrcptParameter ------------------------------------------------

/// The Orcpt parameter to the ESMTP RCPT command
///
/// # Definition
///
/// ```text
/// original-recipient-address = addr-type ";" xtext
/// addr-type = atom
/// ```
///
/// See RFC 3461, section 4.2.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrcptParameter {
    pub addr_type: DsnAddressType,
    pub addr: Xtext,
}

impl OrcptParameter {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        rule::group(buf, |buf| {
            let addr_type = try_ready!(DsnAddressType::parse(buf));
            try_ready!(token::skip_octet(buf, b';'));
            let addr = try_ready!(Xtext::parse(buf));
            Ok(Async::Ready(OrcptParameter{addr_type: addr_type, addr: addr}))
        })
    }
}


//------------ Path ----------------------------------------------------------

/// A path.
///
/// # Definition
///
/// ```text
/// Path           = "<" [ A-d-l ":" ] Mailbox ">"
///
/// A-d-l          = At-domain *( "," At-domain )
///                ; Note that this form, the so-called "source
///                ; route", MUST BE accepted, SHOULD NOT be
///                ; generated, and SHOULD be ignored.
///
/// At-domain      = "@" Domain
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Path(Mailbox);

impl Path {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        rule::group(buf, |buf| {
            try_ready!(token::skip_octet(buf, b'<'));
            try_ready!(skip_a_d_l(buf));
            let res = try_ready!(Mailbox::parse(buf));
            try_ready!(token::skip_octet(buf, b'>'));
            Ok(Async::Ready(Path(res)))
        })
    }
}

fn skip_a_d_l(buf: &mut EasyBuf) -> Poll<(), TokenError> {
    if !try_ready!(skip_at_domain(buf)) {
        return Ok(Async::Ready(()))
    }
    while try_ready!(token::skip_opt_octet(buf, b',')) {
        if !try_ready!(skip_at_domain(buf)) {
            return Err(TokenError)
        }
    }
    try_ready!(token::skip_octet(buf, b':'));
    Ok(Async::Ready(()))
}

fn skip_at_domain(buf: &mut EasyBuf) -> Poll<bool, TokenError> {
    if !try_ready!(token::skip_opt_octet(buf, b'@')) {
        return Ok(Async::Ready(false))
    }
    try_ready!(Domain::skip(buf));
    Ok(Async::Ready(true))
}


//------------ QuotedString -------------------------------------------------

/// A quoted string.
///
/// This type contains the string in its escaped form. Use the `decode()`
/// method to get a version with the escape sequences resolved.
///
/// # Definition
///
/// ```text
/// Quoted-string  = DQUOTE *QcontentSMTP DQUOTE
///
/// QcontentSMTP   = qtextSMTP / quoted-pairSMTP
///
/// quoted-pairSMTP  = %d92 %d32-126
///                  ; i.e., backslash followed by any ASCII
///                  ; graphic (including itself) or SPace
///
/// qtextSMTP      = %d32-33 / %d35-91 / %d93-126
///                ; i.e., within a quoted string, any
///                ; ASCII graphic or space is permitted
///                ; without blackslash-quoting except
///                ; double-quote and the backslash itself.
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotedString(EasyBuf);

impl QuotedString {
    pub fn decode(&self) -> Cow<[u8]> {
        if self.0.as_slice().contains(&b'\\') {
            let mut res = Vec::with_capacity(self.0.len());
            let mut iter = self.0.as_slice().iter();
            while let Some(ch) = iter.next() {
                if *ch == b'\\' {
                    res.push(*iter.next().unwrap());
                }
                else {
                    res.push(*ch)
                }
            }
            Cow::Owned(res)
        }
        else {
            Cow::Borrowed(self.0.as_slice())
        }
    }
}

impl QuotedString {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        rule::group(buf, |buf| {
            try_ready!(core::skip_dquote(buf));
            let res = try_ready!(token::parse(buf, qcontent));
            try_ready!(core::skip_dquote(buf));
            Ok(Async::Ready(QuotedString(res)))
        })
    }
}

fn qcontent(token: &mut Token) -> Poll<(), TokenError> {
    loop {
        if !try_ready!(token::opt_cats(token, test_qtext))
                && !try_ready!(opt_quoted_pair(token)) {
            return Ok(Async::Ready(()))
        }
    }
}

fn test_qtext(ch: u8) -> bool {
    ch == 32 || ch == 33 || (ch >= 35 && ch <= 91) || (ch <= 93 && ch <= 126)
}

fn opt_quoted_pair(token: &mut Token) -> Poll<bool, TokenError> {
    if !try_ready!(token::opt_octet(token, 92)) {
        return Ok(Async::Ready(false))
    }
    try_ready!(token::cat(token, |ch| ch >= 32 && ch <= 126));
    Ok(Async::Ready(true))
}


//------------ RcptPath -----------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RcptPath {
    DomainPostmaster(Domain),
    Postmaster,
    ForwardPath(Path)
}

impl RcptPath {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        try_fail!(Self::parse_domain_postmaster(buf));
        try_fail!(token::translate_literal(buf, b"<Postmaster>",
                                           RcptPath::Postmaster));
        try_fail!(Self::parse_forward_path(buf));
        Err(TokenError)
    }

    fn parse_domain_postmaster(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        try_ready!(token::skip_literal(buf, b"<Postmaster@"));
        let res = try_ready!(Domain::parse(buf));
        try_ready!(token::skip_octet(buf, b'>'));
        Ok(Async::Ready(RcptPath::DomainPostmaster(res)))
    }

    fn parse_forward_path(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        Ok(Async::Ready(RcptPath::ForwardPath(
            try_ready!(Path::parse(buf))
        )))
    }
}


//------------ RetValue -----------------------------------------------------

/// The RET parameter of the ESMTP MAIL command
///
/// See RFC 3461, section 4.3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetValue {
    Full,
    Hdrs,
}

impl RetValue {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        try_fail!(token::translate_literal(buf, b"FULL", RetValue::Full));
        try_fail!(token::translate_literal(buf, b"HDRS", RetValue::Hdrs));
        Err(TokenError)
    }
}


//------------ ReversePath ---------------------------------------------------

/// A reverse path.
///
/// # Definition
///
/// ```text
/// Reverse-path   = Path / "<>"
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReversePath {
    Path(Path),
    Empty
}

impl ReversePath {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        try_fail!(token::translate_literal(buf, b"<>", ReversePath::Empty));
        try_fail!(Self::parse_path(buf));
        Err(TokenError)
    }

    fn parse_path(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        Ok(Async::Ready(ReversePath::Path(
            try_ready!(Path::parse(buf))
        )))
    }
}


//------------ Word ----------------------------------------------------------

/// A word. RFC 5321 calls it a ‘String.’
///
/// # Definition
///
/// ```text
/// > String         = Atom / Quoted-string
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Word {
    Atom(EasyBuf),
    Quoted(QuotedString)
}

impl Word {
    pub fn decode(&self) -> Cow<[u8]> {
        match *self {
            Word::Atom(ref buf) => Cow::Borrowed(buf.as_slice()),
            Word::Quoted(ref quoted) => quoted.decode(),
        }
    }
}

impl Word {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        try_fail!(Self::parse_atom(buf));
        try_fail!(Self::parse_quoted(buf));
        Err(TokenError)
    }

    fn parse_atom(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        Ok(Async::Ready(Word::Atom(try_ready!(parse_atom(buf)))))
    }

    fn parse_quoted(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        Ok(Async::Ready(Word::Quoted(try_ready!(QuotedString::parse(buf)))))
    }
}


//------------ Xtext --------------------------------------------------------

/// Some xtext.
///
/// # Definition
///
/// This is defined in RFC 3461.
///
/// ```text
/// xtext = *( xchar / hexchar )
///
/// xchar = any ASCII CHAR between "!" (33) and "~" (126) inclusive,
///         except for "+" and "=".
///
/// ; "hexchar"s are intended to encode octets that cannot appear
/// ; as ASCII characters within an esmtp-value.
///
/// hexchar = ASCII "+" immediately followed by two upper case
///           hexadecimal digits
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Xtext(EasyBuf);

impl Xtext {
    pub fn decode(&self) -> Cow<[u8]> {
        if self.0.as_slice().contains(&b'+') {
            let mut res = Vec::with_capacity(self.0.len());
            let mut iter = self.0.as_slice().iter();
            while let Some(ch) = iter.next() {
                if ch == &b'+' {
                    let upper = (*iter.next().unwrap() as char)
                                    .to_digit(16).unwrap() as u8;
                    let lower = (*iter.next().unwrap() as char)
                                    .to_digit(16).unwrap() as u8;
                    res.push(upper << 4 | lower);
                }
                else {
                    res.push(*ch)
                }
            }
            Cow::Owned(res)
        }
        else {
            Cow::Borrowed(self.0.as_slice())
        }
    }
}

impl Xtext {
    pub fn parse(buf: &mut EasyBuf) -> Poll<Self, TokenError> {
        Ok(Async::Ready(Xtext(try_ready!(token::parse(buf, Self::token)))))
    }

    pub fn token(token: &mut Token) -> Poll<(), TokenError> {
        if !try_ready!(token::opt_cats(token, test_xchar))
                && !try_ready!(opt_hexchar(token)) {
            return Err(TokenError)
        }
        loop {
            if !try_ready!(token::opt_cats(token, test_xchar))
                    && !try_ready!(opt_hexchar(token)) {
                return Ok(Async::Ready(()))
            }
        }
    }
}

fn test_xchar(ch: u8) -> bool {
    (ch >= 33 && ch <= 60) || (ch >= 62 && ch <= 126)
}

fn opt_hexchar(token: &mut Token) -> Poll<bool, TokenError> {
    if !try_ready!(token::opt_octet(token, b'+')) {
        return Ok(Async::Ready(false))
    }
    try_ready!(core::hexdig(token));
    try_ready!(core::hexdig(token));
    Ok(Async::Ready(true))
}

//============ Parsing Components ============================================

//------------ atom ----------------------------------------------------------
//
// Atom = 1*atext
//
// The definition of atext comes from RFC 5321:
//
// atext          =   ALPHA / DIGIT /    ; Printable US-ASCII
//                    "!" / "#" /        ;  characters not including
//                    "$" / "%" /        ;  specials.  Used for atoms.
//                    "&" / "'" /
//                    "*" / "+" /
//                    "-" / "/" /
//                    "=" / "?" /
//                    "^" / "_" /
//                    "`" / "{" /
//                    "|" / "}" /
//                    "~"

fn test_atext(ch: u8) -> bool {
    (ch >= 0x21 && ch <= 0x27) || ch == 0x2A || ch == 0x2B ||
    ch == 0x2D || (ch >= 0x2F && ch <= 0x39) || ch == 0x3D ||
    ch == 0x3F || (ch >= 0x41 && ch <= 0x5A) ||
    (ch >= 0x5E && ch <= 0x7E) || ch >= 0x80
}

fn atom(token: &mut Token) -> Poll<(), TokenError> {
    token::cats(token, test_atext)
}

fn parse_atom(buf: &mut EasyBuf) -> Poll<EasyBuf, TokenError> {
    token::parse(buf, atom)
}


//------------ sub_domain ----------------------------------------------------
//
// sub-domain     = Let-dig [Ldh-str]

fn sub_domain(token: &mut Token) -> Poll<(), TokenError> {
    try_ready!(let_dig(token));
    try_ready!(ldh_str(token));
    Ok(Async::Ready(()))
}


//------------ let_dig and ldh_str -------------------------------------------
//
// Let-dig        = ALPHA / DIGIT
//
// Ldh-str        = *( ALPHA / DIGIT / "-" ) Let-dig

fn test_let_dig(ch: u8) -> bool {
    core::test_alpha(ch) || core::test_digit(ch)
}

fn let_dig(token: &mut Token) -> Poll<(), TokenError> {
    token::cat(token, test_let_dig)
}

fn ldh_str(token: &mut Token) -> Poll<(), TokenError> {
    // Any sequence of dashes needs to be followed by a let-dig or else we
    // need to end before the sequence.
    loop {
        try_ready!(token::cats(token, test_let_dig));
        if try_ready!(token::opt_octet(token, b'-')) {
            let mut end = 0;
            for (i, ch) in token.as_slice().iter().enumerate() {
                if test_let_dig(*ch) {
                    end = i;
                    break;
                }
                else if *ch != b'-' {
                    return Ok(Async::Ready(()))
                }
            }
            token.advance(end);
        }
        else {
            return Ok(Async::Ready(()))
        }
    }
}

fn parse_ldh_str(buf: &mut EasyBuf) -> Poll<EasyBuf, TokenError> {
    token::parse(buf, ldh_str)
}


//------------ dcontent ------------------------------------------------------
//
// dcontent = %d33-90 / %d94-126

fn test_dcontent(ch: u8) -> bool {
    (ch >= 33 && ch <= 90) || (ch >= 94 && ch <= 126)
}

fn dcontents(token: &mut Token) -> Poll<(), token::TokenError> {
    token::cats(token, test_dcontent)
}

fn parse_dcontents(buf: &mut EasyBuf) -> Poll<EasyBuf, token::TokenError> {
    token::parse(buf, dcontents)
}


//============ Errors =======================================================

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandError;

impl From<token::TokenError> for CommandError {
    fn from(_: token::TokenError) -> Self {
        CommandError
    }
}


//============ Mail Data Handling ============================================

pub fn split_mail_data(buf: &mut EasyBuf) -> Option<EasyBuf> {
    let mut pos = None;
    for (i, slice) in buf.as_slice().windows(5).enumerate() {
        if slice == b"\r\n.\r\n" {
            pos = Some(i);
            break;
        }
    }
    match pos {
        Some(pos) => {
            // The first CRLF is considered part of the data.
            let res = buf.drain_to(pos + 2);
            buf.drain_to(3);
            Some(res)
        }
        None => None
    }
}


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use super::*;

    fn buf(slice: &[u8]) -> EasyBuf { EasyBuf::from(Vec::from(slice)) }

    #[test]
    fn ehlo_command() {
        assert_eq_ready!(
            Command::parse(&mut buf(b"EHLO example.com\r\n")),
            Command::Ehlo(Domain(buf(b"example.com")).into())
        );
        assert_eq_ready!(
            Command::parse(&mut buf(b"EHLO example.com  \r\n")),
            Command::Ehlo(Domain(buf(b"example.com")).into())
        );
    }

    #[test]
    fn mail_command() {
        let path = ReversePath::Path(
            Path(Mailbox { local: LocalPart::Dotted(buf(b"test")),
                           domain: Domain(buf(b"example.com")).into()
        }));
        assert_eq_ready!(
            Command::parse(&mut buf(b"MAIL FROM:<test@example.com>\r\n")),
            Command::Mail(path.clone(), MailParameters::default())
        );
        assert_eq_ready!(
            Command::parse(&mut buf(b"MAIL FROM:<test@example.com> \t \
                                    BODY=7BIT  RET=FULL\r\n")),
            Command::Mail(path.clone(),
                          MailParameters { body: Some(BodyValue::SevenBit),
                                           ret: Some(RetValue::Full),
                                           .. MailParameters::default() })
        );
        assert_eq_ready!(
            Command::parse(&mut buf(b"MAIL FROM:<test@example.com> \t \
                                    BODY=7BIT \t RET=FULL \r\n")),
            Command::Mail(path.clone(),
                          MailParameters { body: Some(BodyValue::SevenBit),
                                           ret: Some(RetValue::Full),
                                           .. MailParameters::default() })
        );
    }

    #[test]
    fn local_part() {
        assert_eq_ready!(LocalPart::parse(&mut buf(b"foo ")),
                         LocalPart::Dotted(buf(b"foo")));
        assert_eq_ready!(LocalPart::parse(&mut buf(b"foo.bar.bazz ")),
                         LocalPart::Dotted(buf(b"foo.bar.bazz")));
    }

    #[test]
    fn address_literal() {
        assert_eq!(
            AddressLiteral::parse(&mut buf(b"[127.0.0.1]")),
            Ok(Async::Ready(AddressLiteral::Ipv4(Ipv4Addr::new(127,0,0,1))))
        );
        assert_eq!(
            AddressLiteral::parse(&mut buf(b"[IPv6:::]")),
            Ok(Async::Ready(
                AddressLiteral::Ipv6(Ipv6Addr::new(0,0,0,0,0,0,0,0)))
            )
        );
        assert_eq!(
            AddressLiteral::parse(&mut buf(b"[foo:bar]")),
            Ok(Async::Ready(
                AddressLiteral::General {
                    tag: buf(b"foo"),
                    content: buf(b"bar")
                }
            ))
        );
    }
}
