#![no_std]

extern "C" {
    fn mBufferNew() -> i32;
    fn mBufferGetArgument(argIndex: i32, bufferHandle: i32) -> i32;
    fn mBufferStorageStore(keyHandle: i32, valueHandle: i32) -> i32;
    fn mBufferStorageLoad(keyHandle: i32, bufferHandle: i32) -> i32;
    fn mBufferFinish(bufferHandle: i32) -> i32;
    fn mBufferGetLength(bufferHandle: i32) -> i32;
}

#[no_mangle]
pub extern "C" fn init() {}

// stores 2 arbitrary (key, value) pairs in ONE execution - same transaction, same account flush
#[no_mangle]
pub extern "C" fn store2() {
    unsafe {
        let k1 = mBufferNew();
        let v1 = mBufferNew();
        let k2 = mBufferNew();
        let v2 = mBufferNew();
        mBufferGetArgument(0, k1);
        mBufferGetArgument(1, v1);
        mBufferGetArgument(2, k2);
        mBufferGetArgument(3, v2);
        mBufferStorageStore(k1, v1);
        mBufferStorageStore(k2, v2);
    }
}

// stores 1 (key, value) pair - for the deterministic cross-tx variant
#[no_mangle]
pub extern "C" fn store1() {
    unsafe {
        let k = mBufferNew();
        let v = mBufferNew();
        mBufferGetArgument(0, k);
        mBufferGetArgument(1, v);
        mBufferStorageStore(k, v);
    }
}

#[no_mangle]
pub extern "C" fn load1() {
    unsafe {
        let k = mBufferNew();
        let v = mBufferNew();
        mBufferGetArgument(0, k);
        let _ = mBufferStorageLoad(k, v);
        mBufferFinish(v);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
