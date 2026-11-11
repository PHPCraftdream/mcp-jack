use super::{invalid, RotationError, MAX_TRUST_SNAPSHOT_BYTES};
use crate::encoding::encode_b64url;
use rustix::fs::{self, AtFlags, Mode, OFlags};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

fn unavailable() -> RotationError { invalid("rotation_state_unavailable") }
fn unknown() -> RotationError { invalid("rotation_state_unknown") }

fn random<const N: usize>() -> Result<String, RotationError> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|_| unavailable())?;
    if bytes.iter().all(|byte| *byte == 0) { return Err(unavailable()); }
    Ok(encode_b64url(&bytes))
}

fn directory(path: &Path) -> Result<File, RotationError> {
    let uid = rustix::process::geteuid().as_raw();
    if uid != rustix::process::getuid().as_raw() || !path.is_absolute()
        || path.as_os_str().as_bytes().len() > 4096
    { return Err(unavailable()); }
    let mut normalized = PathBuf::from("/");
    let mut current = File::from(fs::open("/", OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|_| unavailable())?);
    let validate = |file: &File, parent: bool| -> Result<(), RotationError> {
        let metadata = file.metadata().map_err(|_| unavailable())?;
        let mode = metadata.mode();
        if !metadata.is_dir() || (metadata.uid() != uid && metadata.uid() != 0)
            || (mode & 0o022 != 0 && !(metadata.uid() == 0 && mode & 0o1000 != 0))
            || (parent && (metadata.uid() != uid || mode & 0o7777 != 0o700))
        { return Err(unavailable()); }
        Ok(())
    };
    validate(&current, false)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = File::from(fs::openat(&current, name, OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::empty()).map_err(|_| unavailable())?);
                validate(&current, false)?;
                normalized.push(name);
            }
            _ => return Err(unavailable()),
        }
    }
    if normalized.as_os_str().as_bytes() != path.as_os_str().as_bytes() { return Err(unavailable()); }
    validate(&current, true)?;
    let kind = fs::fstatfs(&current).map_err(|_| unavailable())?.f_type;
    if ![0xef53, 0x58465342, 0x9123683e].contains(&(i128::from(kind) & 0xffff_ffff)) { return Err(unavailable()); }
    Ok(current)
}

fn size(file: &File, maximum: usize) -> Result<usize, RotationError> {
    let metadata = file.metadata().map_err(|_| unavailable())?;
    if !metadata.is_file() || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600 || metadata.nlink() != 1
        || metadata.len() == 0 || metadata.len() > u64::try_from(maximum).map_err(|_| unavailable())?
    { return Err(unavailable()); }
    usize::try_from(metadata.len()).map_err(|_| unavailable())
}

fn read_at(parent: &File, name: &std::ffi::OsStr, maximum: usize) -> Result<Vec<u8>, RotationError> {
    let mut file = File::from(fs::openat(parent, name, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty()).map_err(|_| unavailable())?);
    let length = size(&file, maximum)?;
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes).map_err(|_| unavailable())?;
    let mut extra = [0];
    if file.read(&mut extra).map_err(|_| unavailable())? != 0 || size(&file, maximum)? != length { return Err(unavailable()); }
    Ok(bytes)
}

fn write_file(mut file: File, bytes: &[u8]) -> Result<(), RotationError> {
    file.write_all(bytes).map_err(|_| unknown())?;
    if size(&file, MAX_TRUST_SNAPSHOT_BYTES)? != bytes.len() { return Err(unknown()); }
    file.sync_all().map_err(|_| unknown())
}

/// Внутренний lifetime owner; Drop не удаляет marker и не подтверждает clean state.
pub(super) struct FileOwner {
    parent: File,
    parent_path: PathBuf,
    name: OsString,
    marker_name: OsString,
    marker: Vec<u8>,
    fenced: bool,
    closed: bool,
}

impl FileOwner {
    fn acquire(path: &Path) -> Result<Self, RotationError> {
        let parent_path = path.parent().ok_or_else(unavailable)?.to_path_buf();
        let name = path.file_name().ok_or_else(unavailable)?.to_os_string();
        let mut canonical = parent_path.clone();
        canonical.push(&name);
        if canonical.as_os_str().as_bytes() != path.as_os_str().as_bytes() { return Err(unavailable()); }
        let parent = directory(&parent_path)?;
        let mut marker_name = name.clone();
        marker_name.push(".owner");
        let marker = format!("mcp-jack/rotation-owner/v1\n{}\n", random::<32>()?).into_bytes();
        let file = fs::openat(&parent, marker_name.as_os_str(), OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::RUSR | Mode::WUSR).map_err(|_| unavailable())?;
        write_file(File::from(file), &marker)?;
        parent.sync_all().map_err(|_| unknown())?;
        Ok(Self { parent, parent_path, name, marker_name, marker, fenced: false, closed: false })
    }

    pub(super) fn create_unused(path: &Path, bytes: &[u8]) -> Result<Self, RotationError> {
        Self::bounded(bytes)?;
        let mut owner = Self::acquire(path)?;
        let file = match fs::openat(&owner.parent, owner.name.as_os_str(), OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::RUSR | Mode::WUSR) {
            Ok(file) => file,
            Err(_) => { let _ = owner.close(); return Err(unavailable()); }
        };
        if write_file(File::from(file), bytes).and_then(|()| owner.parent.sync_all().map_err(|_| unknown())).is_err() {
            owner.fence();
            return Err(unknown());
        }
        Ok(owner)
    }

    pub(super) fn open(path: &Path) -> Result<Self, RotationError> {
        let mut owner = Self::acquire(path)?;
        if owner.read().is_err() { let _ = owner.close(); return Err(unavailable()); }
        Ok(owner)
    }

    fn bounded(bytes: &[u8]) -> Result<(), RotationError> {
        if bytes.is_empty() || bytes.len() > MAX_TRUST_SNAPSHOT_BYTES { return Err(unavailable()); }
        Ok(())
    }

    fn ensure(&mut self) -> Result<(), RotationError> {
        if self.closed || self.fenced { return Err(unavailable()); }
        let result = (|| {
            let current = directory(&self.parent_path)?;
            let left = current.metadata().map_err(|_| unavailable())?;
            let right = self.parent.metadata().map_err(|_| unavailable())?;
            if left.dev() != right.dev() || left.ino() != right.ino()
                || read_at(&self.parent, &self.marker_name, 128)? != self.marker
            { return Err(unavailable()); }
            Ok(())
        })();
        if result.is_err() { self.fenced = true; return Err(unknown()); }
        Ok(())
    }

    pub(super) fn read(&mut self) -> Result<Vec<u8>, RotationError> {
        self.ensure()?;
        read_at(&self.parent, &self.name, MAX_TRUST_SNAPSHOT_BYTES)
    }

    pub(super) fn replace(&mut self, expected: &[u8], desired: &[u8]) -> Result<(), RotationError> {
        self.ensure()?;
        Self::bounded(expected)?;
        Self::bounded(desired)?;
        if self.read()? != expected { return Err(invalid("rotation_state_changed")); }
        let temporary = OsString::from(format!(".mcp-jack-{}.tmp", random::<16>()?));
        let result = (|| {
            let file = fs::openat(&self.parent, temporary.as_os_str(), OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC, Mode::RUSR | Mode::WUSR).map_err(|_| unknown())?;
            write_file(File::from(file), desired)?;
            self.ensure()?;
            #[cfg(test)]
            super::store_tests::crash_boundary("before-rename");
            fs::renameat(&self.parent, temporary.as_os_str(), &self.parent, self.name.as_os_str()).map_err(|_| unknown())?;
            #[cfg(test)]
            super::store_tests::crash_boundary("after-rename");
            self.parent.sync_all().map_err(|_| unknown())
        })();
        if result.is_err() { self.fenced = true; return Err(unknown()); }
        Ok(())
    }

    pub(super) fn fence(&mut self) { self.fenced = true; }

    pub(super) fn close(&mut self) -> Result<(), RotationError> {
        if self.closed { return Ok(()); }
        self.ensure()?;
        if fs::unlinkat(&self.parent, self.marker_name.as_os_str(), AtFlags::empty()).is_err() || self.parent.sync_all().is_err() {
            self.fenced = true;
            return Err(unknown());
        }
        self.closed = true;
        Ok(())
    }
}
