#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::XskMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

#[map]
static mut XSK: XskMap = XskMap::with_max_entries(64, 0);

#[xdp]
pub fn minotaur_xdp(ctx: XdpContext) -> u32 {
    match try_minotaur_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_minotaur_xdp(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "Packet received");
    
    // "Slow Path": Redirect to AF_XDP socket in userspace for deep analysis
    // In a real scenario, we would filter first. Here we redirect everything for the demo.
    // The queue_id (0) would be dynamic in a multi-queue setup.
    unsafe {
        return Ok(XSK.redirect(0, 0).unwrap_or(xdp_action::XDP_PASS));
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
