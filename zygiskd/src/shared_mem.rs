// Src/shared mem.rs
use memfd::{MemfdOptions, FileSeal, SealsHashSet};
use std::io::Write;
use std::mem;
use std::os::fd::OwnedFd;
use log::{info, warn};

pub const MAX_MODULES: usize = 32;
pub const MAX_DENYLIST: usize = 1024;
pub const MAX_PATH_LEN: usize = 256;
pub const MAX_PROCESS_LEN: usize = 128;
pub const ZYGISK_SHARED_MAGIC: u32 = 0x4E454F00; // "neo"

#[repr(C, packed)]
pub struct SharedModule {
    pub path: [u8; MAX_PATH_LEN],
}

#[repr(C, packed)]
pub struct SharedDenyEntry {
    pub process: [u8; MAX_PROCESS_LEN],
}

#[repr(C, packed)]
pub struct ZygiskSharedData {
    pub magic: u32,
    pub module_count: u32,
    pub modules: [SharedModule; MAX_MODULES],
    pub deny_count: u32,
    pub deny_list: [SharedDenyEntry; MAX_DENYLIST],
    pub manager_app: [u8; MAX_PROCESS_LEN],
}

impl ZygiskSharedData {
    pub fn new() -> Self {
        unsafe { mem::zeroed() }
    }
}

/// Creates the memfd (anonymous memory), writes the data and seals it.
/// Returns the File Descriptor that we will then pass to Zygote via socket.
pub fn create_shared_memory_fd(module_names: &[String]) -> Option<OwnedFd> {
    let opts = MemfdOptions::default().allow_sealing(true);
    let memfd = match opts.create("jit-cache") {
        Ok(m) => m,
        Err(e) => {
            warn!("Failed to create shared memfd: {}", e);
            return None;
        }
    };

    let mut data = ZygiskSharedData::new();
    data.magic = ZYGISK_SHARED_MAGIC;

    // We fill the list of modules
    data.module_count = std::cmp::min(module_names.len(), MAX_MODULES) as u32;
    for (i, name) in module_names.iter().take(MAX_MODULES).enumerate() {
        let bytes = name.as_bytes();
        let len = std::cmp::min(bytes.len(), MAX_PATH_LEN - 1);
        data.modules[i].path[..len].copy_from_slice(&bytes[..len]);
    }
    
    data.deny_count = 0;

    let bytes = unsafe {
        std::slice::from_raw_parts(
            &data as *const _ as *const u8,
            mem::size_of::<ZygiskSharedData>(),
        )
    };

    let mut file = memfd.into_file();
    if let Err(e) = file.write_all(bytes) {
        warn!("Failed to write to shared memfd: {}", e);
        return None;
    }

    // We seal the file so that no one else can modify it (read only)
    let mut seals = memfd::SealsHashSet::new();
    seals.insert(FileSeal::SealShrink);
    seals.insert(FileSeal::SealGrow);
    seals.insert(FileSeal::SealWrite);
    seals.insert(FileSeal::SealSeal);
    
    // We do not know if the sealing fails due to compatibility issues.
    let _ = memfd::Memfd::try_from_file(file.try_clone().unwrap())
        .map(|m| m.add_seals(&seals));

    info!("Shared memory memfd created and populated.");
    Some(OwnedFd::from(file))
}
