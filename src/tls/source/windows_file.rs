//! Windows counterpart of the tenant-file descriptor walk.
//!
//! Canonicalization has already resolved stable aliases inside the permitted
//! root. Below that trusted root, each NtCreateFile call names ONE component
//! relative to a held directory handle and opens the reparse point itself.
//! Every returned handle is checked before traversal/read; no full-path reopen
//! or reparse fallback is permitted. Denying write/delete sharing prevents data
//! writes and replacement. Attribute-only handles can still retag a directory:
//! OBJ_DONT_REPARSE and final handle-path checks cover that separate transition.
//!
//! Local bindings follow tls/private_file.rs and admin/audit.rs. Layouts and
//! constants follow winternl.h / ntdef.h / winbase.h; no transitive dependency.
//! https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile

use std::ffi::{OsStr, OsString, c_void};
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, Prefix};

type Handle = *mut c_void;

const FILE_READ_DATA: u32 = 0x0001;
const FILE_TRAVERSE: u32 = 0x0020;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_SHARE_READ: u32 = 0x0001;
const FILE_OPEN: u32 = 1;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0020;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
const FILE_TYPE_DISK: u32 = 1;
const FILE_STANDARD_INFO_CLASS: i32 = 1;
const FILE_ATTRIBUTE_TAG_INFO_CLASS: i32 = 9;
const CSTR_EQUAL: i32 = 2;
const OBJ_DONT_REPARSE: u32 = 0x1000;
const MAX_WINDOWS_PATH_UNITS: usize = 32_768;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: Handle,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
union StatusOrPointer {
    status: i32,
    pointer: *mut c_void,
}

#[repr(C)]
struct IoStatusBlock {
    status: StatusOrPointer,
    information: usize,
}

#[repr(C)]
#[derive(Default)]
struct FileAttributeTagInfo {
    attributes: u32,
    reparse_tag: u32,
}

#[repr(C)]
#[derive(Default)]
struct FileStandardInfo {
    allocation_size: i64,
    end_of_file: i64,
    number_of_links: u32,
    delete_pending: u8,
    directory: u8,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut Handle,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandleEx(
        file: Handle,
        class: i32,
        information: *mut c_void,
        size: u32,
    ) -> i32;
    fn GetFileType(file: Handle) -> u32;
    fn GetFinalPathNameByHandleW(file: Handle, path: *mut u16, capacity: u32, flags: u32) -> u32;
    fn CompareStringOrdinal(
        first: *const u16,
        first_len: i32,
        second: *const u16,
        second_len: i32,
        ignore_case: i32,
    ) -> i32;
}

fn refused() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}

fn same_name(first: &OsStr, second: &OsStr, ignore_case: bool) -> bool {
    if !ignore_case {
        return first == second;
    }
    let first: Vec<u16> = first.encode_wide().collect();
    let second: Vec<u16> = second.encode_wide().collect();
    let (Ok(first_len), Ok(second_len)) = (i32::try_from(first.len()), i32::try_from(second.len()))
    else {
        return false;
    };
    // SAFETY: the counted UTF-16 buffers remain valid throughout the call.
    // API failure returns zero and therefore refuses the comparison.
    unsafe {
        CompareStringOrdinal(first.as_ptr(), first_len, second.as_ptr(), second_len, 1)
            == CSTR_EQUAL
    }
}

fn same_prefix(first: Prefix<'_>, second: Prefix<'_>) -> bool {
    match (first, second) {
        (Prefix::Disk(a) | Prefix::VerbatimDisk(a), Prefix::Disk(b) | Prefix::VerbatimDisk(b)) => {
            a.eq_ignore_ascii_case(&b)
        }
        (
            Prefix::UNC(a, b) | Prefix::VerbatimUNC(a, b),
            Prefix::UNC(c, d) | Prefix::VerbatimUNC(c, d),
        ) => same_name(a, c, true) && same_name(b, d, true),
        // Device namespaces and arbitrary verbatim object-manager paths are
        // not filesystem tenant roots. Canonical DOS/UNC paths are supported.
        _ => false,
    }
}

/// Static admission accepts ordinary Windows case/DOS-verbatim spellings.
/// Canonical containment uses exact normal names, preserving case-sensitive
/// directory boundaries; the actual open is always anchored to the root handle.
pub(super) fn strip_root<'a>(path: &'a Path, root: &Path, lexical: bool) -> Option<&'a Path> {
    if !path.is_absolute() || !root.is_absolute() {
        return None;
    }
    let mut path_components = path.components();
    for root_component in root.components() {
        let component = path_components.next()?;
        let same = match (component, root_component) {
            (Component::Prefix(a), Component::Prefix(b)) => same_prefix(a.kind(), b.kind()),
            (Component::RootDir, Component::RootDir) => true,
            (Component::Normal(a), Component::Normal(b)) => same_name(a, b, lexical),
            _ => false,
        };
        if !same {
            return None;
        }
    }
    Some(path_components.as_path())
}

fn check_handle(file: &File, directory: bool) -> io::Result<()> {
    let mut attributes = FileAttributeTagInfo::default();
    let mut standard = FileStandardInfo::default();
    // SAFETY: File owns a live handle; both repr(C) buffers have the documented
    // layout and writable size. Nothing is inspected if either query fails.
    let (disk, attributes_ok, standard_ok) = unsafe {
        (
            GetFileType(file.as_raw_handle()) == FILE_TYPE_DISK,
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FILE_ATTRIBUTE_TAG_INFO_CLASS,
                (&mut attributes as *mut FileAttributeTagInfo).cast(),
                size_of::<FileAttributeTagInfo>() as u32,
            ),
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FILE_STANDARD_INFO_CLASS,
                (&mut standard as *mut FileStandardInfo).cast(),
                size_of::<FileStandardInfo>() as u32,
            ),
        )
    };
    if !disk
        || attributes_ok == 0
        || standard_ok == 0
        || attributes.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || attributes.reparse_tag != 0
        || (attributes.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (standard.directory != 0) != directory
        || standard.delete_pending != 0
    {
        return Err(refused());
    }
    Ok(())
}

fn final_path(file: &File) -> io::Result<std::path::PathBuf> {
    let mut path = vec![0u16; MAX_WINDOWS_PATH_UNITS];
    // SAFETY: live owned handle and a bounded writable UTF-16 buffer. Flags=0
    // requests the normalized DOS/UNC path, matching std::fs::canonicalize.
    // Unsupported metadata/remote normalization is a refusal, never a reopen.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            0,
        )
    } as usize;
    if length == 0 || length >= path.len() || path[..length].contains(&0) {
        return Err(refused());
    }
    Ok(OsString::from_wide(&path[..length]).into())
}

fn open_component(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    let mut name: Vec<u16> = name.encode_wide().collect();
    // NtCreateFile receives a counted ONE-component relative name. Colons
    // would select an alternate data stream; separators/NUL/traversal could
    // reinterpret it. Ordinary filesystem names are not DOS-device aliases
    // under this already-open disk directory handle.
    if name.is_empty()
        || name
            .iter()
            .any(|unit| matches!(*unit, 0 | 0x2f | 0x5c | 0x3a))
        || name == [0x2e]
        || name == [0x2e, 0x2e]
    {
        return Err(refused());
    }
    let length = name
        .len()
        .checked_mul(2)
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(refused)?;
    let mut unicode = UnicodeString {
        length,
        maximum_length: length,
        buffer: name.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: parent.as_raw_handle(),
        object_name: &mut unicode,
        // Refuse any reparse encountered in relative lookup, including an
        // attribute-only retag of the parent. Unsupported flags fail closed.
        attributes: OBJ_DONT_REPARSE,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut status_block = IoStatusBlock {
        status: StatusOrPointer { status: 0 },
        information: 0,
    };
    let mut handle = std::ptr::null_mut();
    // SAFETY: all counted buffers/structures and the owned parent handle stay
    // alive until this synchronous existing-only open completes. No handle
    // inheritance, creation, object-manager absolute path or backup privilege.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_READ_ATTRIBUTES
                | SYNCHRONIZE
                | if directory {
                    FILE_TRAVERSE
                } else {
                    FILE_READ_DATA
                },
            &attributes,
            &mut status_block,
            std::ptr::null(),
            0,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: translation consumes only the returned NTSTATUS value.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    if handle.is_null() || handle == (-1isize as Handle) {
        return Err(refused());
    }
    // SAFETY: a non-error NtCreateFile result produced this new owned handle.
    // File closes it on every later rejection as well as after bounded reading.
    let file = unsafe { File::from_raw_handle(handle) };
    if status != 0 {
        return Err(refused());
    }
    check_handle(&file, directory)?;
    Ok(file)
}

pub(super) fn open(root: &Path, resolved: &Path) -> io::Result<File> {
    let relative = strip_root(resolved, root, false).ok_or_else(refused)?;
    let names = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(refused()),
        })
        .collect::<io::Result<Vec<_>>>()?;
    let Some((last, directories)) = names.split_last() else {
        return Err(refused());
    };
    // The only full-path open is the operator-controlled canonical root.
    // OPEN_REPARSE_POINT covers root replacement too; root ancestors are trusted.
    // No write/delete sharing on held nodes: data writes and renaming cannot
    // race inspection/read. Attribute-only reparse changes are handled by
    // no-reparse lookup, reinspection and final handle identity below.
    // Contention is a refusal, retried on the next load.
    let root_file = OpenOptions::new()
        .access_mode(FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(root)?;
    check_handle(&root_file, true)?;
    let opened_root = final_path(&root_file)?;
    if !strip_root(&opened_root, root, false)
        .is_some_and(|relative| relative.as_os_str().is_empty())
    {
        return Err(refused());
    }
    // Retain ALL ancestors until final opening/inspection has completed.
    let mut parents = vec![root_file];
    for name in directories {
        let parent = parents.last().ok_or_else(refused)?;
        check_handle(parent, true)?;
        parents.push(open_component(parent, name, true)?);
    }
    let parent = parents.last().ok_or_else(refused)?;
    check_handle(parent, true)?;
    let file = open_component(parent, last, false)?;
    for parent in &parents {
        check_handle(parent, true)?;
    }
    // Check the actual final object while all ancestors are still held. Even a
    // filesystem that reparses a retagged RootDirectory must not return bytes
    // from an outside object. The later bounded read uses THIS owned handle.
    let opened_file = final_path(&file)?;
    if strip_root(&opened_file, &opened_root, false) != Some(relative) {
        return Err(refused());
    }
    Ok(file)
}
