#![warn(clippy::all)]

use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use serde::Serialize;
use std::fmt;
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::SystemTime;
use uuid::Uuid;

pub use ::log::Level;

lazy_static! {
    static ref LOG_CONF: Mutex<LogConf> = {
        Mutex::new(LogConf::new())
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConf {
    pub min_level: Level,
    pub hostname: String,
    pub env: String,
    pub app_name: String,
    pub app_version: String,
    pub api_key: String,
    pub log_host: String,
    pub log_port: u16,
}

impl std::default::Default for LogConf {
    fn default() -> Self {
        LogConf {
            min_level: Level::Info,
            hostname: hostname::get_hostname().unwrap_or_else(||"<hostname>".into()),
            env: std::env::var("ENV").unwrap_or_else(|_| "development".to_string()),
            app_name: "<app name>".into(),
            app_version: "<app version>".into(),
            api_key: "".into(),
            log_host: "logrelay.lookback.io".into(),
            log_port: 6514,
        }
    }
}

impl LogConf {
    pub fn new() -> Self {
        LogConf {
            ..Default::default()
        }
    }
    pub fn use_syslog(&self) -> bool {
        !self.api_key.is_empty()
    }
}

// lazy_static! {
//     static ref LOG_MIN_LEVEL: Level = {
//         level_from_str(
//             std::env::var("LOG_MIN_LEVEL")
//                 .unwrap_or_else(|_| "Info".to_string())
//                 .as_str(),
//         )
//     };
//     static ref LOG_USE_SYSLOG: bool = { std::env::var("SYSLOG_API_KEY").is_ok() };
//     static ref SYSLOG_API_KEY: String =
//         { std::env::var("SYSLOG_API_KEY").unwrap_or_else(|_| "".to_string()) };
// }

pub fn log(level: Level, message: &str) -> LogBuilder {
    LogBuilder {
        level,
        message: message.to_string(),
        ..Default::default()
    }
}

pub fn log_level_enabled(level: Level) -> bool {
    let conf = LOG_CONF.lock().unwrap();
    conf.min_level.as_u8() >= level.as_u8()
}

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
        let conf = {
            LOG_CONF.lock().unwrap().clone()
        };
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
    pub fn timestamp(mut self, timestamp: SystemTime) -> LogBuilder {
        self.timestamp = timestamp;
        self
    }
    pub fn subname(mut self, subname: &str) -> LogBuilder {
        self.namespace = format!("{}.{}", self.namespace, subname);
        self
    }
    pub fn data<T: Serialize>(mut self, data: &T) -> LogBuilder {
        let data = serde_json::to_string(data).expect("Failed to serialize json");
        self.actual_data.replace(data);
        self.with_wk().data.replace("***DATA_GOES_HERE***");
        self
    }
    pub fn data_s(mut self, data: &str) -> LogBuilder {
        self.actual_data.replace(data.to_string());
        self.with_wk().data.replace("***DATA_GOES_HERE***");
        self
    }
    pub fn recording_id(mut self, recording_id: &str) -> LogBuilder {
        self.with_wk().recordingId.replace(recording_id.to_string());
        self
    }
    pub fn user_id(mut self, user_id: &str) -> LogBuilder {
        self.with_wk().userId.replace(user_id.to_string());
        self
    }
    pub fn maybe_user_id(mut self, user_id: &Option<String>) -> LogBuilder {
        if let Some(user_id) = user_id {
            self.with_wk().userId.replace(user_id.clone());
        }
        self
    }
    pub fn user_ip(mut self, user_ip: &str) -> LogBuilder {
        self.with_wk().userIp.replace(user_ip.to_string());
        self
    }
    pub fn use_uuid(mut self, use_uuid: bool) -> LogBuilder {
        self.use_uuid = use_uuid;
        self
    }
    pub fn send(self) {
        do_log(self);
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
                (&ws).replace("\"***DATA_GOES_HERE***\"", &d).to_string()
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
            message: format!("{} {}", self.message, self.json_extra(),),
            hostname: &self.conf.hostname,
            timestamp: &self.timestamp,
            msg_id: if self.use_uuid {
                Uuid::new_v4().to_string()
            } else {
                "".to_string()
            },
            app_name: &self.namespace,
            pid: &self.conf.app_version,
            api_key_name: &self.conf.app_name,
            api_key: &self.conf.api_key,
            env: &self.conf.env,
        }
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

fn do_log(l: LogBuilder) {
    if l.conf.min_level.as_u8() < l.level.as_u8() {
        return;
    }
    if l.level.severity().is_none() {
        return;
    }
    if !l.conf.use_syslog() {
        eprintln!("{}", l);
        return;
    }

    use rustls::ClientConfig;
    use rustls::ClientSession;
    use rustls::StreamOwned;
    use std::io::Write;
    use std::sync::Arc;

    lazy_static! {
        static ref TLS_CONF: Arc<ClientConfig> = {
            let mut config = ClientConfig::new();
            config
                .root_store
                .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
            Arc::new(config)
        };
        static ref SOCKET: Mutex<Option<StreamOwned<ClientSession, TcpStream>>> =
            { Mutex::new(None) };
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
                    // wrap tcp in an ssl session
                    let sni = webpki::DNSNameRef::try_from_ascii_str(&l.conf.log_host).unwrap();
                    let sess = rustls::ClientSession::new(&*TLS_CONF, sni);
                    *lock = Some(StreamOwned::new(sess, tcp));
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
        return Err(LologError::new(500, &format!("No ip address for {}", hostname)));
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
    api_key_name: &'a str,
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
            self.api_key_name, self.api_key, self.env
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
    fn enabled(&self, _metadata: &::log::Metadata) -> bool {
        let conf = LOG_CONF.lock().unwrap();
        _metadata.target().starts_with(&conf.app_name)
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
pub struct LologError {
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

impl std::error::Error for LologError {
}

#[macro_export]
macro_rules! xtrace {
    ($($arg:tt)*) => (
        $crate::lolog::log($crate::lolog::Level::Trace, &format!($($arg)*));
    )
}

#[macro_export]
macro_rules! xdebug {
    ($($arg:tt)*) => (
        $crate::lolog::log($crate::lolog::Level::Debug, &format!($($arg)*));
    )
}

#[macro_export]
macro_rules! xinfo {
    ($($arg:tt)*) => (
        $crate::lolog::log($crate::lolog::Level::Info, &format!($($arg)*));
    )
}

#[macro_export]
macro_rules! xwarn {
    ($($arg:tt)*) => (
        $crate::lolog::log($crate::lolog::Level::Warn, &format!($($arg)*));
    )
}

#[macro_export]
macro_rules! xerror {
    ($($arg:tt)*) => (
        $crate::lolog::log($crate::lolog::Level::Error, &format!($($arg)*));
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
            .data(&RandomStuff { stuff: 42 })
            .use_uuid(false);
        let row = format!("{}", build.to_syslog());
        assert_eq!(
            row,
            "<142>1 2019-03-18T13:12:27.000+00:00 my-host fumar \
                1.2.3 - [fumar@53595 apiKey=\"secret stuffz\" env=\"development\"] \
                Hello world! {\"recordingId\":\"abc123\",\"data\":{\"stuff\":42}}\n"
        );
    }
}
