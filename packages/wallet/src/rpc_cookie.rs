//! Linux descriptor-relative, no-follow acquisition of the daemon cookie.
use crate::{rpc::RpcRefusal, rpc_secret::Buffer};
use std::{
    fs::{File, Metadata, OpenOptions},
    os::{
        fd::AsRawFd as _,
        unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    },
    path::Path,
};

// Linux UAPI flags; this acquisition profile is admitted only on Linux.
const NOFOLLOW: i32 = 0x2_0000;
const DIRECTORY: i32 = 0x1_0000;
const NONBLOCK: i32 = 0x800;
const COOKIE_BYTES: usize = 76;

pub(crate) fn open(path: &Path, directory: bool) -> Result<File, RpcRefusal> {
    OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | NONBLOCK | if directory { DIRECTORY } else { 0 })
        .open(path)
        .map_err(|_| RpcRefusal::Cookie)
}

fn metadata(file: &File) -> Result<Metadata, RpcRefusal> {
    file.metadata().map_err(|_| RpcRefusal::Cookie)
}

fn directory(meta: &Metadata, uid: u32, immediate: bool) -> Result<(), RpcRefusal> {
    // POSIX ACL effective permissions are bounded by the group-class mask,
    // represented in st_mode. A zero mask grants no named-user/group access.
    if !meta.is_dir()
        || (meta.uid() != 0 && meta.uid() != uid)
        || meta.mode() & 0o7022 != 0
        || (immediate && (meta.uid() != uid || meta.mode() & 0o7777 != 0o700))
    {
        return Err(RpcRefusal::Cookie);
    }
    Ok(())
}

fn regular(meta: &Metadata, uid: u32) -> Result<(), RpcRefusal> {
    if !meta.is_file()
        || meta.uid() != uid
        || meta.nlink() != 1
        || !matches!(meta.mode() & 0o7777, 0o400 | 0o600)
        || !(75..=76).contains(&meta.len())
    {
        return Err(RpcRefusal::Cookie);
    }
    Ok(())
}

fn same(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.uid() == right.uid()
}

pub(crate) fn grammar(bytes: &[u8]) -> Result<&[u8], RpcRefusal> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if bytes.len() != 75
        || !bytes.starts_with(b"__cookie__:")
        || !bytes[11..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(RpcRefusal::Cookie);
    }
    Ok(bytes)
}

pub(crate) fn acquire(root: &File, path: &[u8], uid: u32) -> Result<Buffer, RpcRefusal> {
    if !cfg!(target_os = "linux")
        || path.len() > 4096
        || path.starts_with(b"/")
        || std::fs::metadata("/proc/self").map_err(|_| RpcRefusal::Cookie)?.uid() != uid
    {
        return Err(RpcRefusal::Cookie);
    }
    // The kernel-owned procfs descriptor directory supplies descriptor-relative
    // access without an unsafe syscall wrapper. Only its fd link is followed;
    // each deployment component is opened with O_NOFOLLOW while its parent lives.
    directory(&metadata(root)?, uid, true)?;
    let mut parent = root.try_clone().map_err(|_| RpcRefusal::Cookie)?;
    let mut ancestors = Vec::new();
    let mut components = path.split(|byte| *byte == b'/').peekable();
    let mut leaf = None;
    while let Some(component) = components.next() {
        if component.is_empty() || component == b"." || component == b".." {
            return Err(RpcRefusal::Cookie);
        }
        let last = components.peek().is_none();
        if ancestors.len() >= 64 {
            return Err(RpcRefusal::Cookie);
        }
        directory(&metadata(&parent)?, uid, last)?;
        let prefix = format!("/proc/self/fd/{}/", parent.as_raw_fd());
        let mut name = Buffer::new(prefix.len() + component.len());
        name.append(prefix.as_bytes())?;
        name.append(component)?;
        let file = name.open(!last)?;
        if last {
            leaf = Some((file, name));
        } else {
            let before = metadata(&parent)?;
            ancestors.push((parent, before, name));
            parent = file;
        }
    }
    let (mut file, name) = leaf.ok_or(RpcRefusal::Cookie)?;
    let before = metadata(&file)?;
    let parent_before = metadata(&parent)?;
    regular(&before, uid)?;
    let mut content = Buffer::new(COOKIE_BYTES);
    content.read_cookie(&mut file)?;
    #[cfg(test)]
    tests::AFTER_READ.with(|hook| {
        if let Some(change) = hook.borrow_mut().take() {
            change();
        }
    });
    let after = metadata(&file)?;
    regular(&after, uid)?;
    let current = name.open(false)?;
    if !same(&before, &after) || !same(&after, &metadata(&current)?) || content.len() as u64 != after.len() {
        return Err(RpcRefusal::Cookie);
    }
    if !same(&parent_before, &metadata(&parent)?) {
        return Err(RpcRefusal::Cookie);
    }
    for (index, (directory, before, name)) in ancestors.iter().enumerate() {
        if !same(before, &metadata(directory)?) {
            return Err(RpcRefusal::Cookie);
        }
        let current = name.open(true)?;
        let next = ancestors.get(index + 1).map_or(&parent, |entry| &entry.0);
        if !same(&metadata(&current)?, &metadata(next)?) {
            return Err(RpcRefusal::Cookie);
        }
    }
    content.cookie_grammar()?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        io::Write as _,
        os::unix::fs::{DirBuilderExt as _, PermissionsExt as _, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };
    thread_local! { pub(super) static AFTER_READ: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None); }
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Root(std::path::PathBuf);
    impl Root {
        fn new() -> Self {
            let path = std::path::PathBuf::from(std::env::var_os("TMPDIR").unwrap()).join(format!(
                "wallet-cookie-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn cookie(&self, bytes: &[u8]) {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(self.0.join("cookie"))
                .unwrap();
            file.write_all(bytes).unwrap();
        }
        fn read(&self) -> Result<Buffer, RpcRefusal> {
            acquire(&File::open(&self.0).unwrap(), b"cookie", self.uid())
        }
        fn uid(&self) -> u32 {
            std::fs::metadata(&self.0).unwrap().uid()
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    /// Claim: Cookie grammar accepts precisely the daemon username, sixty-four lowercase hexadecimal digits and an optional single LF, refusing every tested truncation, oversized input and forbidden separator or character.
    /// ´claim:wallet:rpc-cookie-grammar-is-exact´
    /// ´test:unit:grammar-cases´
    #[test]
    fn grammar_cases() {
        let valid = [b"__cookie__:".as_slice(), &[b'a'; 64]].concat();
        assert_eq!(grammar(&valid), Ok(valid.as_slice()));
        let mut newline = valid.clone();
        newline.push(b'\n');
        assert_eq!(grammar(&newline), Ok(valid.as_slice()));
        for end in 0..valid.len() {
            assert_eq!(grammar(&valid[..end]), Err(RpcRefusal::Cookie));
        }
        for position in 0..valid.len() {
            for byte in [0, b' ', b'\r', b'\n', b':', b'A', 255] {
                if valid[position] == byte {
                    continue;
                }
                let mut changed = valid.clone();
                changed[position] = byte;
                assert_eq!(grammar(&changed), Err(RpcRefusal::Cookie));
            }
        }
        for suffix in [b"\r\n".as_slice(), b"\n\n", b"x", b"\nother"] {
            assert_eq!(grammar(&[valid.as_slice(), suffix].concat()), Err(RpcRefusal::Cookie));
        }
    }

    /// Claim: Descriptor acquisition checks the current UID, exact file and root modes, regular single-link files and every traversed directory; symlinks, missing files, substitutions and mutation during reading refuse, while later reads acquire rotated bytes.
    /// ´claim:wallet:rpc-cookie-descriptors-confine-acquisition´
    /// ´test:unit:descriptor-cases´
    #[test]
    fn descriptor_cases() {
        let root = Root::new();
        let valid = [b"__cookie__:".as_slice(), &[b'a'; 64]].concat();
        root.cookie(&valid);
        assert!(root.read().unwrap().equals(&valid));
        let file = root.0.join("cookie");
        for mode in [0o400, 0o600] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(root.read().is_ok());
        }
        for mode in (0..=0o7777).filter(|mode| !matches!(mode, 0o400 | 0o600)) {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(matches!(root.read(), Err(RpcRefusal::Cookie)));
        }
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            regular(&std::fs::metadata(&file).unwrap(), root.uid() + 1),
            Err(RpcRefusal::Cookie)
        );
        assert!(matches!(
            acquire(&File::open(&root.0).unwrap(), b"cookie", root.uid() + 1),
            Err(RpcRefusal::Cookie)
        ));
        for mode in [0o750, 0o770, 0o1700] {
            std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(matches!(root.read(), Err(RpcRefusal::Cookie)));
        }
        std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::hard_link(&file, root.0.join("link")).unwrap();
        assert!(matches!(root.read(), Err(RpcRefusal::Cookie)));
        std::fs::remove_file(root.0.join("link")).unwrap();
        std::fs::rename(&file, root.0.join("saved")).unwrap();
        symlink("saved", &file).unwrap();
        assert!(matches!(root.read(), Err(RpcRefusal::Cookie)));
        std::fs::remove_file(&file).unwrap();
        assert!(matches!(root.read(), Err(RpcRefusal::Cookie)));
        std::fs::create_dir(&file).unwrap();
        assert!(matches!(root.read(), Err(RpcRefusal::Cookie)));
        std::fs::remove_dir(&file).unwrap();
        root.cookie(&valid);
        let changed = file.clone();
        AFTER_READ.with(|hook| *hook.borrow_mut() = Some(Box::new(move || std::fs::write(changed, b"partial").unwrap())));
        assert!(matches!(root.read(), Err(RpcRefusal::Cookie)));
        root.cookie(&valid);
        let changed = file.clone();
        let saved = root.0.join("saved");
        AFTER_READ.with(|hook| *hook.borrow_mut() = Some(Box::new(move || std::fs::rename(saved, changed).unwrap())));
        assert!(matches!(root.read(), Err(RpcRefusal::Cookie)));
        let rotated = [b"__cookie__:".as_slice(), &[b'b'; 64]].concat();
        root.cookie(&rotated);
        assert!(root.read().unwrap().equals(&rotated));
        root.cookie(&[b'a'; 77]);
        assert!(matches!(root.read(), Err(RpcRefusal::Cookie)));
        root.cookie(b"partial");
        assert!(matches!(root.read(), Err(RpcRefusal::Cookie)));
        root.cookie(&valid);
        let directory = root.0.join("nested");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::rename(&file, directory.join("cookie")).unwrap();
        let handle = File::open(&root.0).unwrap();
        assert!(acquire(&handle, b"nested/cookie", root.uid()).is_ok());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            acquire(&handle, b"nested/cookie", root.uid()),
            Err(RpcRefusal::Cookie)
        ));
        symlink("nested", root.0.join("alias")).unwrap();
        assert!(matches!(
            acquire(&handle, b"alias/cookie", root.uid()),
            Err(RpcRefusal::Cookie)
        ));
        for path in [b"../cookie".as_slice(), b"/cookie", b"nested//cookie", b"./cookie"] {
            assert!(matches!(acquire(&handle, path, root.uid()), Err(RpcRefusal::Cookie)));
        }
    }
}
