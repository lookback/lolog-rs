#![warn(clippy::all)]

use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use rustls::ClientConfig;
use rustls::ClientSession;
use rustls::StreamOwned;
use serde::Serialize;
use std::env;
use std::fmt;
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;
use uuid::Uuid;

pub use ::log::Level;
pub use ::log::{debug, error, info, log_enabled, trace, warn};

lazy_static! {
    static ref LOG_CONF: Mutex<LogConf> = { Mutex::new(LogConf::new()) };
}

/// Lolog configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConf {
    /// Minimum visible log level. Defaults to INFO.
    pub min_level: Level,
    /// Hostname of syslog entries from this instance. Default is OS hostname.
    pub hostname: String,
    /// Env of syslog entries. Default is the ENV variable, and otherwise "development".
    pub env: String,
    /// Name of application. This is the default `namespace` in log messages. Can be appended
    /// to, compare `ios` vs `ios.bcast`. It is also used as `api_key_name`.
    pub app_name: String,
    /// Application version string.
    pub app_version: String,
    /// API key id for the api key
    pub api_key_id: String,
    /// API key for loggin to our syslog server.
    pub api_key: String,
    /// Name of host to connect and deliver log messages to.
    pub log_host: String,
    /// Port on host to deliver log messages to.
    pub log_port: u16,
    /// Whether we are to use TLS for logging.
    pub use_tls: bool,
}

impl std::default::Default for LogConf {
    fn default() -> Self {
        LogConf {
            min_level: Level::Info,
            hostname: env::var("SYSLOG_HOSTNAME").unwrap_or_else(|_| {
                hostname::get()
                    .map(|o| o.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| "<hostname>".into())
            }),
            env: env::var("ENV").unwrap_or_else(|_| "development".to_string()),
            app_name: "<app name>".into(),
            app_version: "<app version>".into(),
            api_key_id: env::var("SYSLOG_API_KEY_ID").unwrap_or_else(|_| "".into()),
            api_key: env::var("SYSLOG_API_KEY").unwrap_or_else(|_| "".into()),
            log_host: env::var("SYSLOG_HOST")
                .unwrap_or_else(|_| "logrelay.lookback.io".to_string()),
            log_port: env::var("SYSLOG_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(6514),
            use_tls: env::var("SYSLOG_TLS")
                .map(|x| x == "1" || x == "true")
                .unwrap_or(false),
        }
    }
}

impl LogConf {
    /// Create a new LogConf. Also consider using `Default::default()`.
    pub fn new() -> Self {
        LogConf {
            ..Default::default()
        }
    }
    fn use_syslog(&self) -> bool {
        !self.api_key.is_empty()
    }
}

/// Start logging a simple message to the logger. The returned builder must be called
/// `.send()` upon to actually send the message.
pub fn log(level: Level, message: &str) -> LogBuilder {
    LogBuilder {
        level,
        message: message.to_string(),
        ..Default::default()
    }
}

/// Check if the given log level is enabled.
pub fn log_level_enabled(level: Level) -> bool {
    let conf = LOG_CONF.lock().unwrap();
    conf.min_level.as_u8() >= level.as_u8()
}

/// Log builders allows more fine grained details to be sent to the logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogBuilder {
    conf: LogConf,
    timestamp: SystemTime,
    level: Level,
    namespace: String,
    message: String,
    well_known: Option<WellKnown>,
    actual_data: Option<String>,
    use_uuid: bool,
}

/// Format as a syslog row.
impl fmt::Display for LogBuilder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let dt: DateTime<Utc> = self.timestamp.into();
        // 13:12:27.000
        let time = dt.format("%H:%M:%S%.3f");
        let json_extra = self.json_extra();
        write!(
            f,
            "{} {} {}{}",
            time,
            self.level.to_str(),
            self.message,
            if json_extra.is_empty() {
                "".to_string()
            } else {
                format!(" {}", json_extra)
            }
        )
    }
}

impl std::default::Default for LogBuilder {
    fn default() -> Self {
        let conf = { LOG_CONF.lock().unwrap().clone() };
        let namespace = conf.app_name.to_string();
        LogBuilder {
            conf,
            timestamp: SystemTime::now(),
            level: Level::Info,
            namespace,
            message: "".to_string(),
            well_known: None,
            actual_data: None,
            use_uuid: true,
        }
    }
}

impl LogBuilder {
    /// Add an explicit timestamp to this message.
    pub fn timestamp(mut self, timestamp: SystemTime) -> LogBuilder {
        self.timestamp = timestamp;
        self
    }
    /// Make a subsystem name under the application name. I.e. `ios` vs `ios.bcast`.
    pub fn subname(mut self, subname: &str) -> LogBuilder {
        self.namespace = format!("{}.{}", self.namespace, subname);
        self
    }
    /// Provide some JSON serializable data to be included in the message.
    pub fn data<T: Serialize>(mut self, data: &T) -> LogBuilder {
        let data = serde_json::to_string(data).expect("Failed to serialize json");
        self.actual_data.replace(data);
        self.with_wk().data.replace("***DATA_GOES_HERE***");
        self
    }
    /// Provide some JSON serializable data as a str.
    pub fn data_str(mut self, data: &str) -> LogBuilder {
        self.actual_data.replace(data.to_string());
        self.with_wk().data.replace("***DATA_GOES_HERE***");
        self
    }
    /// Set recording id this log message belongs to.
    pub fn recording_id(mut self, recording_id: &str) -> LogBuilder {
        self.with_wk().recordingId.replace(recording_id.to_string());
        self
    }
    /// Set user id this log message belongs to.
    pub fn user_id(mut self, user_id: &str) -> LogBuilder {
        self.with_wk().userId.replace(user_id.to_string());
        self
    }
    /// Set the user id, if it is there.
    pub fn maybe_user_id(mut self, user_id: &Option<String>) -> LogBuilder {
        if let Some(user_id) = user_id {
            self.with_wk().userId.replace(user_id.clone());
        }
        self
    }
    /// Set the session id this belongs to.
    pub fn session_id(mut self, session_id: &str) -> LogBuilder {
        self.with_wk().sessionId.replace(session_id.to_string());
        self
    }
    /// Set the session id, if it is there.
    pub fn maybe_session_id(mut self, session_id: &Option<String>) -> LogBuilder {
        if let Some(session_id) = session_id {
            self.with_wk().sessionId.replace(session_id.clone());
        }
        self
    }
    /// Provide the user ip address.
    pub fn user_ip(mut self, user_ip: &str) -> LogBuilder {
        self.with_wk().userIp.replace(user_ip.to_string());
        self
    }
    /// Suppress the use of a uuid as msg id, if need be. Default is on.
    pub fn use_uuid(mut self, use_uuid: bool) -> LogBuilder {
        self.use_uuid = use_uuid;
        self
    }
    /// Consume and send this log row.
    pub fn send(self) {
        do_log(self);
    }
    pub fn well_knownable(mut self, wk: &dyn WellKnownable) -> LogBuilder {
        if let Some(recording_id) = wk.recording_id() {
            self.with_wk().recordingId.replace(recording_id);
        }
        if let Some(user_id) = wk.user_id() {
            self.with_wk().userId.replace(user_id);
        }
        if let Some(user_ip) = wk.user_ip() {
            self.with_wk().userIp.replace(user_ip);
        }
        if let Some(session_id) = wk.session_id() {
            self.with_wk().sessionId.replace(session_id);
        }
        self
    }
    fn with_wk(&mut self) -> &mut WellKnown {
        self.well_known.get_or_insert_with(|| WellKnown {
            ..Default::default()
        })
    }
    fn json_extra(&self) -> String {
        if let Some(wk) = &self.well_known {
            let ws = serde_json::to_string(wk).expect("Failed to serialize json");
            if let Some(d) = &self.actual_data {
                (&ws).replace("\"***DATA_GOES_HERE***\"", &d)
            } else {
                ws
            }
        } else {
            "".to_string()
        }
    }
    fn to_syslog(&self) -> SyslogMessage {
        SyslogMessage {
            facility: SyslogFacility::Local1,
            severity: self.level.severity().expect("Translate severity"),
            message: format!("{} {}", strip_ctrl(&self.message), self.json_extra(),),
            hostname: &self.conf.hostname,
            timestamp: &self.timestamp,
            msg_id: if self.use_uuid {
                Uuid::new_v4().to_string()
            } else {
                "".to_string()
            },
            app_name: &self.namespace,
            pid: &self.conf.app_version,
            api_key_id: if self.conf.api_key_id.is_empty() {
                &self.conf.app_name
            } else {
                &self.conf.api_key_id
            },
            api_key: &self.conf.api_key,
            env: &self.conf.env,
        }
    }
}

// replace any char < 32 with a space.
fn strip_ctrl(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\x00'..='\x1f' => ' ',
            _ => c,
        })
        .collect()
}

pub trait WellKnownable {
    fn recording_id(&self) -> Option<String> {
        None
    }
    fn user_id(&self) -> Option<String> {
        None
    }
    fn user_ip(&self) -> Option<String> {
        None
    }
    fn session_id(&self) -> Option<String> {
        None
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq, Default)]
#[allow(non_snake_case)]
struct WellKnown {
    #[serde(skip_serializing_if = "Option::is_none")]
    recordingId: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    userId: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    userIp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sessionId: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<&'static str>,
}

trait LevelExt {
    fn to_str(&self) -> &str;
    fn severity(&self) -> Option<SyslogSeverity>;
    fn as_u8(&self) -> u8;
}

impl LevelExt for Level {
    fn to_str(&self) -> &str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
    fn severity(&self) -> Option<SyslogSeverity> {
        match self {
            Level::Trace => None,
            Level::Debug => Some(SyslogSeverity::Debug),
            Level::Info => Some(SyslogSeverity::Informational),
            Level::Warn => Some(SyslogSeverity::Warning),
            Level::Error => Some(SyslogSeverity::Error),
        }
    }
    fn as_u8(&self) -> u8 {
        match self {
            Level::Trace => 5,
            Level::Debug => 4,
            Level::Info => 3,
            Level::Warn => 2,
            Level::Error => 1,
        }
    }
}

/// Parse a level string such as "info" or "Info" or "INFO" to corresponding level.
/// Handles `trace`, `debug`, `info`, `warn`, and `error`.
pub fn level_from_str(s: &str) -> Level {
    match s.to_lowercase().as_str() {
        "trace" => Level::Trace,
        "debug" => Level::Debug,
        "info" => Level::Info,
        "warn" => Level::Warn,
        "error" => Level::Error,
        _ => Level::Info,
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SyslogFacility {
    Kernel = 0,
    User = 1,
    System = 3,
    Audit = 13,
    Alert = 14,
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SyslogSeverity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Informational = 6,
    Debug = 7,
}

lazy_static! {
    static ref TLS_CONF: Arc<ClientConfig> = {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        Arc::new(config)
    };
    static ref SOCKET: Mutex<Option<Socket>> = { Mutex::new(None) };
}

#[allow(clippy::large_enum_variant)]
enum Socket {
    Tls(StreamOwned<ClientSession, TcpStream>),
    Raw(TcpStream),
}

use std::io;

impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Socket::Tls(v) => v.write(buf),
            Socket::Raw(v) => v.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Socket::Tls(v) => v.flush(),
            Socket::Raw(v) => v.flush(),
        }
    }
}

fn do_log(l: LogBuilder) {
    if l.conf.min_level.as_u8() < l.level.as_u8() {
        return;
    }
    // do print all levels locally.
    if !l.conf.use_syslog() {
        eprintln!("{}", l);
        return;
    }
    // don't send on stuff without severity
    if l.level.severity().is_none() {
        return;
    }

    let mut lock = SOCKET.lock().unwrap();

    let mut attempts = 3;

    loop {
        attempts -= 1;
        if attempts == 0 {
            // give up
            eprintln!("{}", l);
            break;
        }
        if lock.is_none() {
            match connect_host(&l.conf.log_host, l.conf.log_port) {
                Ok(tcp) => {
                    let sock = if l.conf.use_tls {
                        let sni = webpki::DNSNameRef::try_from_ascii_str(&l.conf.log_host).unwrap();
                        let sess = rustls::ClientSession::new(&*TLS_CONF, sni);
                        Socket::Tls(StreamOwned::new(sess, tcp))
                    } else {
                        Socket::Raw(tcp)
                    };
                    *lock = Some(sock);
                }
                Err(_) => {
                    // try again
                    *lock = None;
                    continue;
                }
            }
        }

        // we got a connection
        let row = format!("{}", l.to_syslog());
        let to_send = &row.into_bytes()[..];
        match lock.as_mut().unwrap().write_all(to_send) {
            Ok(_) => break, // success
            Err(_) => {
                // failed to send, try to reinstate a new socket
                *lock = None;
            }
        }
    }
}

use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::time::Duration;

fn connect_host(hostname: &str, port: u16) -> Result<TcpStream, LologError> {
    //
    let ips: Vec<SocketAddr> = format!("{}:{}", hostname, port)
        .to_socket_addrs()
        .map_err(|e| LologError::new(500, &format!("DNS lookup failed ({}): {}", hostname, e)))?
        .collect();

    if ips.is_empty() {
        return Err(LologError::new(
            500,
            &format!("No ip address for {}", hostname),
        ));
    }

    // pick first ip, or should we randomize?
    let sock_addr = ips[0];

    // connect with a configured timeout.
    let stream = TcpStream::connect_timeout(&sock_addr, Duration::from_millis(5_000))
        .map_err(|err| LologError::new(500, &format!("{}", err)))?;

    stream
        .set_read_timeout(Some(Duration::from_millis(10_000)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(15_000)))
        .ok();

    Ok(stream)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyslogMessage<'a> {
    facility: SyslogFacility,
    severity: SyslogSeverity,
    timestamp: &'a SystemTime,
    hostname: &'a str,
    app_name: &'a str,
    pid: &'a str,
    msg_id: String,
    api_key_id: &'a str,
    api_key: &'a str,
    env: &'a str,
    message: String,
}

/// Format as a syslog row.
impl<'a> fmt::Display for SyslogMessage<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let pri = (self.facility as u8) * 8 + (self.severity as u8);
        let dt: DateTime<Utc> = self.timestamp.clone().into();
        // 2019-03-18T13:12:27.000+00:00
        let time = dt.format("%Y-%m-%dT%H:%M:%S%.3f%:z");
        let newline = if self.message.ends_with('\n') {
            ""
        } else {
            "\n"
        };
        // 53595 is an private enterprise number (PEN) for Lookback
        // as assigned by IANA. https://www.iana.org/assignments/enterprise-numbers
        // we applied for it here:
        // https://pen.iana.org/pen/PenApplication.page
        let strct = format!(
            "[{}@53595 apiKey=\"{}\" env=\"{}\"]",
            self.api_key_id, self.api_key, self.env
        );
        write!(
            f,
            "<{}>1 {} {} {} {} {} {} {}{}",
            pri,
            time,
            chk(self.hostname),
            chk(self.app_name),
            chk(self.pid),
            chk(&self.msg_id),
            strct,
            chk(&self.message),
            newline
        )
    }
}

fn chk(s: &str) -> &str {
    if s.is_empty() {
        "-"
    } else {
        s
    }
}

struct SimpleLogger;

impl ::log::Log for SimpleLogger {
    fn enabled(&self, metadata: &::log::Metadata) -> bool {
        let conf = LOG_CONF.lock().unwrap();
        metadata.target().starts_with(&conf.app_name) || metadata.target().starts_with("hreq::")
    }

    fn log(&self, record: &::log::Record) {
        if self.enabled(record.metadata()) {
            log(
                match record.level() {
                    ::log::Level::Trace => Level::Trace,
                    ::log::Level::Debug => Level::Debug,
                    ::log::Level::Info => Level::Info,
                    ::log::Level::Warn => Level::Warn,
                    ::log::Level::Error => Level::Error,
                },
                &format!("{}", record.args()),
            )
            .send();
        }
    }

    fn flush(&self) {}
}

use ::log::LevelFilter;

static LOGGER: SimpleLogger = SimpleLogger;

/// Configure the logger by providing the conf for it.
pub fn setup_logger(conf: LogConf) {
    let mut lock = LOG_CONF.lock().unwrap();
    *lock = conf;
    static INIT: ::std::sync::Once = ::std::sync::Once::new();
    INIT.call_once(|| {
        ::log::set_logger(&LOGGER)
            .map(|()| ::log::set_max_level(LevelFilter::Trace))
            .expect("Failed to set logger")
    });
}

#[derive(Debug, Clone)]
struct LologError {
    code: u16,
    message: String,
}

impl LologError {
    fn new(code: u16, message: &str) -> Self {
        LologError {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for LologError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LologError {}

/// Create a log builder for the TRACE level.
#[macro_export]
macro_rules! xtrace {
    ($($arg:tt)*) => (
        ::lolog::log(::lolog::Level::Trace, &format!($($arg)*));
    )
}

/// Create a log builder for the DEBUG level.
#[macro_export]
macro_rules! xdebug {
    ($($arg:tt)*) => (
        ::lolog::log(::lolog::Level::Debug, &format!($($arg)*));
    )
}

/// Create a log builder for the INFO level.
#[macro_export]
macro_rules! xinfo {
    ($($arg:tt)*) => (
        ::lolog::log(::lolog::Level::Info, &format!($($arg)*));
    )
}

/// Create a log builder for the WARN level.
#[macro_export]
macro_rules! xwarn {
    ($($arg:tt)*) => (
        ::lolog::log(::lolog::Level::Warn, &format!($($arg)*));
    )
}

/// Create a log builder for the ERROR level.
#[macro_export]
macro_rules! xerror {
    ($($arg:tt)*) => (
        ::lolog::log(::lolog::Level::Error, &format!($($arg)*));
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[derive(Serialize, Debug, Clone, PartialEq, Eq, Default)]
    struct RandomStuff {
        stuff: usize,
    }

    #[test]
    fn test_strip_ctrl() {
        assert_eq!(strip_ctrl("foo\nbar"), "foo bar");
    }

    #[test]
    fn test_translate_syslog() {
        setup_logger(LogConf {
            hostname: "my-host".into(),
            api_key: "secret stuffz".into(),
            app_name: "fumar".into(),
            app_version: "1.2.3".into(),
            ..Default::default()
        });
        ::std::env::set_var("SYSLOG_API_KEY", "secret stuffz");
        let now = UNIX_EPOCH + Duration::from_secs(1_552_914_747);
        let build = log(Level::Info, "Hello world!")
            .timestamp(now)
            .recording_id("abc123")
            .user_id("martin")
            .session_id("my session")
            .data(&RandomStuff { stuff: 42 })
            .use_uuid(false);
        let row = format!("{}", build.to_syslog());
        assert_eq!(
            row,
            "<142>1 2019-03-18T13:12:27.000+00:00 my-host fumar \
             1.2.3 - [fumar@53595 apiKey=\"secret stuffz\" env=\"development\"] \
             Hello world! {\"recordingId\":\"abc123\",\"userId\":\"martin\",\
             \"sessionId\":\"my session\",\"data\":{\"stuff\":42}}\n"
        );
    }
}
