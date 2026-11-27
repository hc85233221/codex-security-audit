"""Private report I/O and redirection guards. No writes to inspected sources."""
import ctypes
import json
import os
from pathlib import Path
import stat


def is_redirected(path):
    """Reject symlinks and Windows junctions/cloud reparse points in any ancestor."""
    path = Path(path).absolute()
    for item in (path,) + tuple(path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            return True
    return False


def write_new(path, value, is_json=True):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) if is_json else value)
        stream.write('\n')


def private_directory(path):
    path = Path(path)
    if is_redirected(path):
        raise ValueError('Report location must not use symlinks or reparse points.')
    if path.exists():
        raise FileExistsError('Choose a new report directory.')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != 'nt':
        path.mkdir(mode=0o700)
        return 'POSIX directory 0700; report files 0600'
    # Windows mode=0600 is NOT a DACL. Create the directory with an explicit
    # protected, inheritable DACL before writing any collected information.
    from ctypes import wintypes as w
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    a = ctypes.WinDLL('advapi32', use_last_error=True)
    def api(lib, name, restype, args):
        f = getattr(lib, name); f.restype = restype; f.argtypes = args; return f
    close = api(k, 'CloseHandle', w.BOOL, [w.HANDLE])
    free = api(k, 'LocalFree', w.HANDLE, [w.HANDLE])
    vol = ctypes.create_unicode_buffer(32768)
    getvol = api(k, 'GetVolumePathNameW', w.BOOL, [w.LPCWSTR, w.LPWSTR, w.DWORD])
    if not getvol(str(path.parent), vol, len(vol)):
        raise ctypes.WinError(ctypes.get_last_error())
    drive = api(k, 'GetDriveTypeW', w.UINT, [w.LPCWSTR])
    if drive(vol.value) != 3:
        raise ValueError('Use a local fixed disk for private reports.')
    flags = w.DWORD()
    getinfo = api(k, 'GetVolumeInformationW', w.BOOL,
                 [w.LPCWSTR, w.LPWSTR, w.DWORD, ctypes.POINTER(w.DWORD),
                  ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD), w.LPWSTR, w.DWORD])
    if not getinfo(vol.value, None, 0, None, None, ctypes.byref(flags), None, 0) or not flags.value & 8:
        raise ValueError('Report disk must support persistent access-control lists (NTFS/ReFS).')
    current = api(k, 'GetCurrentProcess', w.HANDLE, [])
    opentoken = api(a, 'OpenProcessToken', w.BOOL, [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)])
    tokeninfo = api(a, 'GetTokenInformation', w.BOOL,
                    [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)])
    convertsid = api(a, 'ConvertSidToStringSidW', w.BOOL, [w.LPVOID, ctypes.POINTER(w.LPWSTR)])
    token = w.HANDLE(); sid_text = w.LPWSTR(); descriptor = w.LPVOID()
    if not opentoken(current(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        size = w.DWORD(); tokeninfo(token, 1, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        if not tokeninfo(token, 1, buf, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(w.LPVOID))[0]
        if not convertsid(sid_ptr, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        sddl = 'D:P(A;OICI;FA;;;%s)(A;OICI;FA;;;SY)' % sid_text.value
        convert = api(a, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', w.BOOL,
                      [w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.DWORD)])
        if not convert(sddl, 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        class SecurityAttributes(ctypes.Structure):
            _fields_ = [('length', w.DWORD), ('descriptor', w.LPVOID), ('inherit', w.BOOL)]
        sa = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        create = api(k, 'CreateDirectoryW', w.BOOL, [w.LPCWSTR, ctypes.POINTER(SecurityAttributes)])
        if not create(str(path), ctypes.byref(sa)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if descriptor: free(descriptor)
        if sid_text: free(ctypes.cast(sid_text, w.HANDLE))
        close(token)
    return 'Windows protected DACL: current user and SYSTEM; inherited by new report files'


class WindowsJob:
    """Bound only our waiting worker and its subsequently created descendants."""
    def __init__(self, process):
        from ctypes import wintypes as w
        self.k = ctypes.WinDLL('kernel32', use_last_error=True)
        class Basic(ctypes.Structure):
            _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                        ('flags', w.DWORD), ('min_ws', ctypes.c_size_t), ('max_ws', ctypes.c_size_t),
                        ('active', w.DWORD), ('affinity', ctypes.c_size_t),
                        ('priority', w.DWORD), ('scheduling', w.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in
                        ('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')]
        class Extended(ctypes.Structure):
            _fields_ = [('basic', Basic), ('io', IO), ('process_mem', ctypes.c_size_t),
                        ('job_mem', ctypes.c_size_t), ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]
        self.k.CreateJobObjectW.argtypes = [w.LPVOID, w.LPCWSTR]; self.k.CreateJobObjectW.restype = w.HANDLE
        self.k.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD]
        self.k.SetInformationJobObject.restype = w.BOOL
        self.k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]; self.k.AssignProcessToJobObject.restype = w.BOOL
        self.k.CloseHandle.argtypes = [w.HANDLE]; self.k.CloseHandle.restype = w.BOOL
        self.handle = self.k.CreateJobObjectW(None, None)
        if not self.handle: raise ctypes.WinError(ctypes.get_last_error())
        limits = Extended(); limits.basic.flags = 0x2000
        if (not self.k.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits))
                or not self.k.AssignProcessToJobObject(self.handle, w.HANDLE(int(process._handle)))):
            error = ctypes.get_last_error(); self.close(); raise ctypes.WinError(error)

    def close(self):
        if self.handle:
            self.k.CloseHandle(self.handle); self.handle = None
