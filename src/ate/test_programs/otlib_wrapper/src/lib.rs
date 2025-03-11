// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use opentitanlib::app::TransportWrapper;
use opentitanlib::backend;
use opentitanlib::backend::chip_whisperer::ChipWhispererOpts;
use opentitanlib::backend::proxy::ProxyOpts;
use opentitanlib::backend::ti50emulator::Ti50EmulatorOpts;
use opentitanlib::backend::verilator::VerilatorOpts;
use opentitanlib::io::jtag::{JtagParams, JtagTap};
use opentitanlib::test_utils::init::InitializeTest;
use opentitanlib::test_utils::load_bitstream::LoadBitstream;
use opentitanlib::test_utils::load_sram_program::{
    ExecutionMode, ExecutionResult, SramProgramParams,
};

#[no_mangle]
pub extern "C" fn OtLibFpgaInit(
    fpga: *mut c_char,
    fpga_bitstream: *mut c_char,
) -> *const TransportWrapper {
    // Unsupported backends.
    let empty_proxy_opts = ProxyOpts {
        proxy: None,
        port: 0,
    };
    let empty_ti50emul_opts = Ti50EmulatorOpts {
        instance_prefix: String::from(""),
        executable_directory: PathBuf::from_str("").unwrap(),
        executable: String::from(""),
    };
    let empty_verilator_opts = VerilatorOpts {
        verilator_bin: String::from(""),
        verilator_rom: String::from(""),
        verilator_flash: vec![],
        verilator_otp: String::from(""),
        verilator_timeout: Duration::from_millis(0),
        verilator_args: vec![],
    };

    // SAFETY: The FPGA string must be defined by the caller and be valid.
    let fpga_cstr = unsafe { CStr::from_ptr(fpga) };
    let fpga_in = fpga_cstr.to_str().unwrap();
    // SAFETY: The FPGA bitstream path string must be defined by the caller and be a valid path.
    let fpga_bitstream_cstr = unsafe { CStr::from_ptr(fpga_bitstream) };
    let fpga_bitstream_in = fpga_bitstream_cstr.to_str().unwrap();

    // Only the hyper310 backend is currently supported.
    let backend_opts = backend::BackendOpts {
        interface: String::from(fpga_in),
        disable_dft_on_reset: false,
        conf: vec![],
        usb_vid: None,
        usb_pid: None,
        usb_serial: None,
        opts: ChipWhispererOpts { uarts: None },
        openocd_adapter_config: None,
        // Unsupported backends.
        verilator_opts: empty_verilator_opts,
        proxy_opts: empty_proxy_opts,
        ti50emulator_opts: empty_ti50emul_opts,
    };

    // Create transport.
    let transport = backend::create(&backend_opts).unwrap();
    transport.apply_default_configuration(None).unwrap();

    // Load bitstream.
    let load_bitstream = LoadBitstream {
        clear_bitstream: true,
        bitstream: Some(PathBuf::from_str(fpga_bitstream_in).unwrap()),
        rom_reset_pulse: Duration::from_millis(50),
        rom_timeout: Duration::from_secs(2),
    };
    InitializeTest::print_result("load_bitstream", load_bitstream.init(&transport)).unwrap();

    Box::into_raw(Box::new(transport))
}

#[no_mangle]
pub extern "C" fn OtLibLoadSramElf(
    transport: &TransportWrapper,
    openocd_path: *mut c_char,
    sram_elf: *mut c_char,
) {
    // Unpack path strings.
    // SAFETY: The OpenOCD path string must be set by the caller and be valid.
    let openocd_path_cstr = unsafe { CStr::from_ptr(openocd_path) };
    let openocd_path_in = openocd_path_cstr.to_str().unwrap();
    // SAFETY: The SRAM ELF path string must be set by the caller and be valid.
    let sram_elf_cstr = unsafe { CStr::from_ptr(sram_elf) };
    let sram_elf_in = sram_elf_cstr.to_str().unwrap();

    // Set CPU TAP straps, reset, and connect to the JTAG interface.
    let jtag_params = JtagParams {
        openocd: PathBuf::from_str(openocd_path_in).unwrap(),
        adapter_speed_khz: 1000,
        log_stdio: false,
    };
    let _ = transport.pin_strapping("PINMUX_TAP_RISCV").unwrap().apply();
    let _ = transport.reset_target(Duration::from_millis(50), true);
    let mut jtag = jtag_params
        .create(transport)
        .unwrap()
        .connect(JtagTap::RiscvTap)
        .unwrap();

    // Reset and halt the CPU to ensure we are in a known state.
    jtag.reset(/*run=*/ false).unwrap();

    // Load the SRAM program into DUT over JTAG and execute it.
    let sram_program = SramProgramParams {
        elf: Some(PathBuf::from_str(sram_elf_in).unwrap()),
        vmem: None,
        load_addr: None,
    };
    let result = sram_program
        .load_and_execute(&mut *jtag, ExecutionMode::Jump)
        .unwrap();
    match result {
        //ExecutionResult::Executing => log::info!("SRAM program loaded and is executing."),
        ExecutionResult::Executing => println!("SRAM program loaded and is executing."),
        _ => panic!("SRAM program load/execution failed: {:?}.", result),
    }

    // Disconnect from JTAG.
    jtag.disconnect().unwrap();
    transport
        .pin_strapping("PINMUX_TAP_RISCV")
        .unwrap()
        .remove()
        .unwrap();
}
