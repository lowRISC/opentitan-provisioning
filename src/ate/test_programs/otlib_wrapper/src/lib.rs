// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use opentitanlib::backend;
use opentitanlib::backend::chip_whisperer::ChipWhispererOpts;
use opentitanlib::backend::proxy::ProxyOpts;
use opentitanlib::backend::ti50emulator::Ti50EmulatorOpts;
use opentitanlib::backend::verilator::VerilatorOpts;
use opentitanlib::test_utils::init::InitializeTest;
use opentitanlib::test_utils::load_bitstream::LoadBitstream;

#[no_mangle]
pub extern "C" fn OtLibFpgaInit(fpga: *mut c_char, fpga_bitstream: *mut c_char) {
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
}
