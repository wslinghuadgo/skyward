//! Opening the data partition and its users' own files on a thread of its
//! own, so the screen keeps up: the keys come from the secure world, and
//! what a user enters at their screen lock is checked slowly on purpose.

use anyhow::Result;
use skyward_binder::driver::Binder;
use skyward_crypto::data::{self, Closed, Opening};
use skyward_crypto::keymint::KeyMint;
use skyward_sys::worker::Worker;
use std::os::fd::RawFd;
use std::path::Path;

pub enum Job {
    /// Open the partition as far as it opens with nothing a user knows.
    Open,
    /// Open the own files of `user` with what they entered at their screen
    /// lock; `closed` are the users whose own files are still closed.
    Unlock { closed: Vec<Closed>, user: u32, credential: Vec<u8> },
}

/// How a job ended: what it opened, or why it did not.
pub enum Ended {
    Opened(Result<Opening, String>),
    Unlocked(Result<Vec<Closed>, String>),
}

/// A job done on a thread of its own, which the screen lets go once the
/// job has ended.
pub struct Decryptor {
    /// Tells how the job ended, once.
    worker: Worker<Ended>,
}

impl Decryptor {
    pub fn start(job: Job) -> Result<Decryptor> {
        let worker = Worker::start("decrypt", move |tell| {
            tell.tell(match job {
                // The programs that hold the keys start behind the screen,
                // so a look taken before they are there waits and looks
                // again rather than saying the partition cannot be opened.
                Job::Open => Ended::Opened(again_while_starting(|| with_data_keys(data::open_without_credential))),
                Job::Unlock { closed, user, credential } => {
                    Ended::Unlocked(with_key_service(|service| data::unlock(service, &closed, user, &credential)))
                }
            });
        })?;
        Ok(Decryptor { worker })
    }

    /// Readable once the job has ended.
    pub fn fd(&self) -> RawFd {
        self.worker.fd()
    }

    /// How the job ended, once it has.
    pub fn ended(&self) -> Option<Ended> {
        self.worker.events().pop()
    }
}

/// What the phone holds where the key service is reached, said beside why
/// it was not: which programs of the service directories run, and where
/// their own programs are.
fn key_diagnostics() -> String {
    let running = |name: &str| {
        std::fs::read_dir("/proc").ok().into_iter().flatten().flatten().any(|entry| {
            entry.file_name().to_string_lossy().bytes().all(|byte| byte.is_ascii_digit())
                && std::fs::read(entry.path().join("cmdline")).is_ok_and(|bytes| String::from_utf8_lossy(&bytes).contains(name))
        })
    };
    let at = |path: &str| if Path::new(path).is_file() { "there" } else { "missing" };
    format!(
        "\n[binder={} servicemanager={} hwservicemanager={} keymint={} servicemanager_bin={} keymint_bin={}]",
        if Path::new("/dev/binder").exists() { "there" } else { "missing" },
        if running("servicemanager") { "running" } else { "not running" },
        if running("hwservicemanager") { "running" } else { "not running" },
        if running("keymint") { "running" } else { "not running" },
        at("/mnt/system/bin/servicemanager"),
        at("/vendor/bin/hw/android.hardware.security.keymint-service-qti"),
    )
}

/// Do `work`, and where it ended because the key service was not running
/// yet, do it again for a while.
fn again_while_starting<T>(work: impl Fn() -> Result<T, String>) -> Result<T, String> {
    let mut waited = 0;
    loop {
        match work() {
            Err(why) if why.contains("is not running") && waited < 20 => {
                std::thread::sleep(std::time::Duration::from_secs(2));
                waited += 1;
            }
            other => return other,
        }
    }
}

/// Do `work` with the phone's key service, reached afresh for it, and say
/// why it failed in words for the page.
pub fn with_key_service<T>(work: impl FnOnce(&KeyMint) -> Result<T>) -> Result<T, String> {
    let done = (|| {
        let binder = Binder::open()?;
        let service = KeyMint::open(&binder)?;
        work(&service)
    })();
    done.map_err(|e| format!("{e:#}{}", key_diagnostics()))
}

/// Do `work` with what reaching the data partition takes: the phone's key
/// service, reached afresh for it, where the phone's own table has the
/// partition encrypted, and nothing where it has not, so that a partition
/// kept as the plain filesystem it is opens on a phone whose key service
/// does not start. Says why it failed in words for the page.
pub fn with_data_keys<T>(work: impl FnOnce(Option<&KeyMint>) -> Result<T>) -> Result<T, String> {
    let done = (|| {
        if !data::keyed()? {
            return work(None);
        }
        let binder = Binder::open()?;
        let service = KeyMint::open(&binder)?;
        work(Some(&service))
    })();
    done.map_err(|e| format!("{e:#}{}", key_diagnostics()))
}
