use nethernet::error::ProtocolError;
use nethernet::protocol::codec::{read_bytes_u32, read_bytes_varuint};
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Cursor;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

struct LargestAllocation;

static LARGEST: AtomicUsize = AtomicUsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());

unsafe impl GlobalAlloc for LargestAllocation {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        if layout.size() > 1 << 20 {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: LargestAllocation = LargestAllocation;

#[test]
fn huge_varuint_length_is_refused_without_allocating_it() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    LARGEST.store(0, Ordering::Relaxed);
    let result = read_bytes_varuint(&mut Cursor::new([0xff, 0xff, 0xff, 0xff, 0x0f, 1, 2]));
    let largest = LARGEST.load(Ordering::Relaxed);
    assert!(result.is_err());
    assert!(
        largest < 1 << 16,
        "allocated {largest} bytes for a 7-byte input"
    );
}

#[test]
fn lengths_above_65535_are_refused() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut varuint = vec![0x80, 0x80, 0x04];
    varuint.resize(3 + 65536, 0);
    assert!(matches!(
        read_bytes_varuint(&mut Cursor::new(varuint)),
        Err(ProtocolError::MessageSizeExceeded(65536))
    ));

    let mut u32_prefixed = 65536u32.to_le_bytes().to_vec();
    u32_prefixed.resize(4 + 65536, 0);
    assert!(matches!(
        read_bytes_u32(&mut Cursor::new(u32_prefixed)),
        Err(ProtocolError::MessageSizeExceeded(65536))
    ));
}

#[test]
fn length_longer_than_the_input_is_an_error() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    LARGEST.store(0, Ordering::Relaxed);
    let result = read_bytes_u32(&mut Cursor::new([0xff, 0xff, 0x00, 0x00, 1, 2]));
    assert!(matches!(result, Err(ProtocolError::Io(_))));
    assert!(LARGEST.load(Ordering::Relaxed) < 1 << 17);
}
