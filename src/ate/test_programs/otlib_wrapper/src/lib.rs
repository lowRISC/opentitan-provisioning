// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::CStr;
use std::io::Write;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::slice;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use arrayvec::ArrayVec;
use crc::{Crc, CRC_32_ISO_HDLC};
use regex::Regex;

use cp_lib::reset_and_lock;
use opentitanlib::app::TransportWrapper;
use opentitanlib::backend;
use opentitanlib::backend::chip_whisperer::ChipWhispererOpts;
use opentitanlib::backend::proxy::ProxyOpts;
use opentitanlib::backend::ti50emulator::Ti50EmulatorOpts;
use opentitanlib::backend::verilator::VerilatorOpts;
use opentitanlib::bootstrap::{BootstrapOptions, BootstrapProtocol};
use opentitanlib::console::spi::SpiConsoleDevice;
use opentitanlib::dif::lc_ctrl::{DifLcCtrlState, LcCtrlReg};
use opentitanlib::io::console::{ConsoleDevice, ConsoleError};
use opentitanlib::io::gpio::{PinMode, PullMode};
use opentitanlib::io::jtag::{JtagParams, JtagTap};
use opentitanlib::io::spi::SpiParams;
use opentitanlib::io::uart::UartParams;
use opentitanlib::test_utils::bootstrap::Bootstrap;
use opentitanlib::test_utils::init::InitializeTest;
use opentitanlib::test_utils::lc_transition::trigger_lc_transition;
use opentitanlib::test_utils::load_bitstream::LoadBitstream;
use opentitanlib::test_utils::load_sram_program::{
    ExecutionMode, ExecutionResult, SramProgramParams,
};
use opentitanlib::uart::console::{ExitStatus, UartConsole};

// NOTE: must match kDutTxMaxSpiFrameSizeInBytes defined in src/ate/ate_api.h
// TODO(timothytrippel): look into using bindgen here to keep in sync
const CONSOLE_BUFFER_MAX_SIZE: usize = 2020;

// NOTE: must match definition of dut_spi_frame_t defined in src/ate/ate_api.h
// TODO(timothytrippel): look into using bindgen here to keep in sync
#[repr(C)]
pub struct DutSpiFrame {
    pub payload: [u8; CONSOLE_BUFFER_MAX_SIZE],
    pub size: usize,
}

#[no_mangle]
pub extern "C" fn OtLibFpgaTransportInit(fpga: *mut c_char) -> *const TransportWrapper {
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

    Box::into_raw(Box::new(transport))
}

#[no_mangle]
pub extern "C" fn OtLibFpgaLoadBitstream(
    transport: *const TransportWrapper,
    fpga_bitstream: *mut c_char,
) {
    // SAFETY: The transport wrapper pointer passed from C side should be the pointer returned by
    // the call to `OtLibFpgaTransportInit(...)` above.
    let transport = unsafe { &*transport };

    // SAFETY: The FPGA bitstream path string must be defined by the caller and be a valid path.
    let fpga_bitstream_cstr = unsafe { CStr::from_ptr(fpga_bitstream) };
    let fpga_bitstream_in = fpga_bitstream_cstr.to_str().unwrap();

    // Load bitstream.
    let load_bitstream = LoadBitstream {
        clear_bitstream: true,
        bitstream: Some(PathBuf::from_str(fpga_bitstream_in).unwrap()),
        rom_reset_pulse: Duration::from_millis(50),
        rom_timeout: Duration::from_secs(2),
    };
    InitializeTest::print_result("load_bitstream", load_bitstream.init(&transport)).unwrap();
}

#[no_mangle]
pub extern "C" fn OtLibLoadSramElf(
    transport: *const TransportWrapper,
    openocd_path: *mut c_char,
    sram_elf: *mut c_char,
    wait_for_done: bool,
    timeout_ms: u64,
) {
    // SAFETY: The transport wrapper pointer passed from C side should be the pointer returned by
    // the call to `OtLibFpgaTransportInit(...)` above.
    let transport: &TransportWrapper = unsafe { &*transport };

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
        skip_crc: false,
    };
    let mut mode = ExecutionMode::Jump;
    if wait_for_done {
        mode = ExecutionMode::JumpAndWait(Duration::from_millis(timeout_ms));
    }
    let result = sram_program.load_and_execute(&mut *jtag, mode).unwrap();
    match result {
        ExecutionResult::Executing => println!("SRAM program loaded and is executing."),
        ExecutionResult::ExecutionDone(_sp) => println!("SRAM program loaded execution completed."),
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

#[no_mangle]
pub extern "C" fn OtLibBootstrap(transport: *const TransportWrapper, bin: *mut c_char) {
    // SAFETY: The transport wrapper pointer passed from C side should be the pointer returned by
    // the call to `OtLibFpgaTransportInit(...)` above.
    let transport: &TransportWrapper = unsafe { &*transport };

    // Unpack path strings.
    // SAFETY: The binary path string must be set by the caller and be valid.
    let bin_cstr = unsafe { CStr::from_ptr(bin) };
    let bin_in = bin_cstr.to_str().unwrap();
    let bin_path = PathBuf::from(bin_in);

    // Bootstrap flash binary into the DUT.
    let bs = Bootstrap {
        options: BootstrapOptions {
            uart_params: UartParams {
                uart: "CONSOLE".to_string(),
                baudrate: None, // Use default baudrate.
                flow_control: false,
            },
            spi_params: SpiParams {
                ..Default::default()
            },
            protocol: BootstrapProtocol::Eeprom,
            clear_uart: None,
            reset_delay: Duration::from_millis(100),
            leave_in_bootstrap: false,
            leave_in_reset: false,
            inter_frame_delay: None,
            flash_erase_delay: None,
        },
        bootstrap: Some(bin_path.clone()),
    };
    let _ = bs
        .load(transport, &bin_path)
        .expect(format!("Failed to bootstrap binary: {:?}.", bin_path).as_str());
}

#[no_mangle]
pub extern "C" fn OtLibConsoleWaitForRx(
    transport: *const TransportWrapper,
    c_msg: *mut c_char,
    timeout_ms: u64,
) {
    // SAFETY: The transport wrapper pointer passed from C side should be the pointer returned by
    // the call to `OtLibFpgaTransportInit(...)` above.
    let transport: &TransportWrapper = unsafe { &*transport };

    // Get handle to SPI console.
    let spi = transport.spi("BOOTSTRAP").unwrap();
    let device_console_tx_ready_pin = &transport.gpio_pin("IOA5").unwrap();
    let _ = device_console_tx_ready_pin
        .set_mode(PinMode::Input)
        .expect("Unable to set GPIO pin mode.");
    let _ = device_console_tx_ready_pin
        .set_pull_mode(PullMode::None)
        .expect("Unable to set GPIO pull mode.");
    let spi_console = SpiConsoleDevice::new(
        &*spi,
        Some(device_console_tx_ready_pin),
        /*ignore_frame_num=*/ true,
    )
    .unwrap();

    // Unpack msg string.
    // SAFETY: The expected message string must be set by the caller and be valid.
    let msg_cstr = unsafe { CStr::from_ptr(c_msg) };
    let msg = msg_cstr.to_str().unwrap();

    // Wait for message to be received over the console.
    let _ = UartConsole::wait_for(&spi_console, msg, Duration::from_millis(timeout_ms)).unwrap();
}

fn check_console_crc(json_str: &str, crc_str: &str) -> Result<()> {
    let crc = crc_str.parse::<u32>()?;
    let actual_crc = Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(json_str.as_bytes());
    if crc != actual_crc {
        return Err(
            ConsoleError::GenericError("CRC didn't match received json body.".into()).into(),
        );
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn OtLibConsoleRx(
    transport: *const TransportWrapper,
    sync_msg: *mut c_char,
    spi_frames: *mut DutSpiFrame,
    num_frames: *mut usize,
    skip_crc_check: bool,
    quiet: bool,
    timeout_ms: u64,
) {
    // SAFETY: The transport wrapper pointer passed from C side should be the pointer returned by
    // the call to `OtLibFpgaTransportInit(...)` above.
    let transport: &TransportWrapper = unsafe { &*transport };

    // Unpack sync_msg string.
    // SAFETY: The expected sync message string must be set by the caller and be valid.
    let sync_msg_cstr = unsafe { CStr::from_ptr(sync_msg) };
    let sync_str = sync_msg_cstr.to_str().unwrap();

    // Get handle to SPI console.
    let spi = transport.spi("BOOTSTRAP").unwrap();
    let device_console_tx_ready_pin = &transport.gpio_pin("IOA5").unwrap();
    let _ = device_console_tx_ready_pin.set_mode(PinMode::Input);
    let _ = device_console_tx_ready_pin.set_pull_mode(PullMode::None);
    let spi_console = SpiConsoleDevice::new(
        &*spi,
        Some(device_console_tx_ready_pin),
        /*ignore_frame_num=*/ true,
    )
    .unwrap();

    // Wait for the sync message over the console.
    if sync_str.len() > 0 {
        let _ = UartConsole::wait_for(&spi_console, sync_str, Duration::from_millis(timeout_ms))
            .expect(&format!("Device sync ({}) message missed.", sync_str).to_string());
    }

    // Instantiate a "UartConsole", which is really just a console buffer.
    let mut console = UartConsole {
        timeout: Some(Duration::from_millis(timeout_ms)),
        timestamp: true,
        newline: true,
        exit_success: Some(Regex::new(r"RESP_OK:(.*) CRC:([0-9]+)\n").unwrap()),
        exit_failure: Some(Regex::new(r"RESP_ERR:(.*) CRC:([0-9]+)\n").unwrap()),
        ..Default::default()
    };

    // Select if we should silence STDOUT.
    let mut stdout = std::io::stdout();
    let out = if !quiet {
        let w: &mut dyn Write = &mut stdout;
        Some(w)
    } else {
        None
    };

    // Receive the payload from DUT.
    // SAFETY: num_frames should be a valid pointer to memory allocated by the caller.
    let num_frames = unsafe { &mut *num_frames };
    // SAFETY: msg should be a valid pointer to memory allocated by the caller.
    let spi_frames = unsafe { std::slice::from_raw_parts_mut(spi_frames, *num_frames) };
    let result = console.interact(&spi_console, None, out).unwrap();
    match result {
        ExitStatus::ExitSuccess => {
            let cap = console
                .captures(ExitStatus::ExitSuccess)
                .expect("RESP_OK capture");
            let json_str = cap.get(1).expect("RESP_OK group").as_str();
            let crc_str = cap.get(2).expect("CRC group").as_str();
            if !skip_crc_check {
                check_console_crc(json_str, crc_str).expect("CRC check failed.");
            }
            let num_frames_required =
                (json_str.len() + CONSOLE_BUFFER_MAX_SIZE - 1) / CONSOLE_BUFFER_MAX_SIZE;
            if *num_frames < num_frames_required {
                panic!(
                        "Not enough frames ({} frames of size {} bytes) allocated to receive JSON string of length {}",
                        *num_frames,
                        CONSOLE_BUFFER_MAX_SIZE,
                        json_str.len()
                    )
            }
            for (i, spi_frame) in spi_frames.iter_mut().enumerate() {
                if i < num_frames_required {
                    let start = i * CONSOLE_BUFFER_MAX_SIZE;
                    let end = (start + CONSOLE_BUFFER_MAX_SIZE).min(json_str.len());
                    let chunk = &json_str.as_bytes()[start..end];
                    let chunk_len = chunk.len();
                    spi_frame.payload[..chunk_len].copy_from_slice(chunk);
                    spi_frame.size = chunk_len;
                } else {
                    break;
                }
            }
            *num_frames = num_frames_required;
        }
        ExitStatus::ExitFailure => {
            let cap = console
                .captures(ExitStatus::ExitFailure)
                .expect("RESP_ERR capture");
            let json_str = cap.get(1).expect("RESP_OK group").as_str();
            let crc_str = cap.get(2).expect("CRC group").as_str();
            check_console_crc(json_str, crc_str).unwrap();
            panic!("{}", json_str)
        }
        ExitStatus::Timeout => panic!("Timed Out"),
        _ => panic!("Impossible result: {:?}", result),
    }
}

#[no_mangle]
pub extern "C" fn OtLibConsoleTx(
    transport: *const TransportWrapper,
    sync_msg: *mut c_char,
    spi_frame: *mut u8,
    spi_frame_size: usize,
    timeout_ms: u64,
) {
    // SAFETY: The transport wrapper pointer passed from C side should be the pointer returned by
    // the call to `OtLibFpgaTransportInit(...)` above.
    let transport: &TransportWrapper = unsafe { &*transport };

    // Unpack sync_msg string.
    // SAFETY: The expected sync message string must be set by the caller and be valid.
    let sync_msg_cstr = unsafe { CStr::from_ptr(sync_msg) };
    let sync_str = sync_msg_cstr.to_str().unwrap();

    // Get handle to SPI console.
    let spi = transport.spi("BOOTSTRAP").unwrap();
    let device_console_tx_ready_pin = &transport.gpio_pin("IOA5").unwrap();
    let _ = device_console_tx_ready_pin.set_mode(PinMode::Input);
    let _ = device_console_tx_ready_pin.set_pull_mode(PullMode::None);
    let spi_console = SpiConsoleDevice::new(
        &*spi,
        Some(device_console_tx_ready_pin),
        /*ignore_frame_num=*/ true,
    )
    .unwrap();

    // Wait for the sync message over the console.
    if sync_str.len() > 0 {
        let _ = UartConsole::wait_for(&spi_console, sync_str, Duration::from_millis(timeout_ms))
            .expect(&format!("Device sync ({}) message missed.", sync_str).to_string());
    }

    // Send data to the DUT over the console.
    let spi_frame_slice = unsafe { slice::from_raw_parts(spi_frame as *const u8, spi_frame_size) };
    spi_console
        .console_write(spi_frame_slice)
        .expect("Unable to write to console.");
}

#[no_mangle]
pub extern "C" fn OtLibResetAndLock(transport: *const TransportWrapper, openocd_path: *mut c_char) {
    // SAFETY: The transport wrapper pointer passed from C side should be the pointer returned by
    // the call to `OtLibFpgaTransportInit(...)` above.
    let transport: &TransportWrapper = unsafe { &*transport };

    // Unpack OpenOCD path string.
    // SAFETY: The OpenOCD path string must be set by the caller and be valid.
    let openocd_path_cstr = unsafe { CStr::from_ptr(openocd_path) };
    let openocd_path_in = openocd_path_cstr.to_str().unwrap();

    // Set CPU TAP straps, reset and lock the chip.
    let jtag_params = JtagParams {
        openocd: PathBuf::from_str(openocd_path_in).unwrap(),
        adapter_speed_khz: 1000,
        log_stdio: false,
    };
    reset_and_lock(transport, &jtag_params, Duration::from_millis(50))
        .expect("Failed to lock the DUT.");
}

#[no_mangle]
pub extern "C" fn OtLibLcTransition(
    transport: *const TransportWrapper,
    openocd_path: *mut c_char,
    token: *const u8,
    token_size: usize,
    target_lc_state: u32,
) {
    // SAFETY: The transport wrapper pointer passed from C side should be the pointer returned by
    // the call to `OtLibFpgaTransportInit(...)` above.
    let transport: &TransportWrapper = unsafe { &*transport };

    // Unpack OpenOCD path string.
    // SAFETY: The OpenOCD path string must be set by the caller and be valid.
    let openocd_path_cstr = unsafe { CStr::from_ptr(openocd_path) };
    let openocd_path_in = openocd_path_cstr.to_str().unwrap();

    // Unpack test unlock token.
    // SAFETY: The test unlock token must be set by the caller and be valid.
    let token_bytes = unsafe { slice::from_raw_parts(token, token_size) };
    let token = token_bytes
        .chunks(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .collect::<ArrayVec<u32, 4>>();

    // Set CPU TAP straps, reset and lock the chip.
    let jtag_params = JtagParams {
        openocd: PathBuf::from_str(openocd_path_in).unwrap(),
        adapter_speed_khz: 1000,
        log_stdio: false,
    };
    let reset_delay = Duration::from_millis(50);

    // Connect to LC TAP.
    transport
        .pin_strapping("ROM_BOOTSTRAP")
        .unwrap()
        .apply()
        .expect("Could not apply bootstrap straps.");
    transport
        .pin_strapping("PINMUX_TAP_LC")
        .unwrap()
        .apply()
        .expect("Could not apply LC TAP straps.");
    transport
        .reset_target(reset_delay, true)
        .expect("Could not reset chip.");
    let mut jtag = jtag_params
        .create(transport)
        .unwrap()
        .connect(JtagTap::LcTap)
        .expect("Could not connect to LC TAP.");

    // Set target LC state and token.
    let lc_state = DifLcCtrlState(target_lc_state);
    let lc_token = if token_size > 0 {
        Some(token.clone().into_inner().unwrap())
    } else {
        None
    };

    // ROM execution is not yet enabled in OTP so we can safely reconnect to the LC TAP after
    // the transition without risking the chip resetting.
    trigger_lc_transition(
        transport,
        jtag,
        lc_state,
        lc_token,
        /*use_external_clk=*/
        false, // AST will be calibrated by now, so no need for ext_clk.
        reset_delay,
        /*reset_tap_straps=*/ Some(JtagTap::LcTap),
    )
    .expect("Could not perform LC transition.");

    // Check that LC state has transitioned to the target state.
    jtag = jtag_params
        .create(transport)
        .unwrap()
        .connect(JtagTap::LcTap)
        .expect("Could not connect to LC TAP.");
    let state = jtag.read_lc_ctrl_reg(&LcCtrlReg::LcState).unwrap();
    assert_eq!(state, lc_state.redundant_encoding());

    jtag.disconnect().expect("Could not disconnect from JTAG.");
    transport
        .pin_strapping("PINMUX_TAP_LC")
        .unwrap()
        .remove()
        .expect("Could not remove LC TAP straps.");
    transport
        .pin_strapping("ROM_BOOTSTRAP")
        .unwrap()
        .remove()
        .expect("Could not remove bootstrap straps.");
}

#[no_mangle]
pub extern "C" fn OtLibCheckTransportImgBoot(
    transport: *const TransportWrapper,
    owner_fw_boot_msg: *mut c_char,
    timeout_ms: u64,
) {
    // SAFETY: The transport wrapper pointer passed from C side should be the pointer returned by
    // the call to `OtLibFpgaTransportInit(...)` above.
    let transport: &TransportWrapper = unsafe { &*transport };

    // Unpack boot message string.
    // SAFETY: The boot message string must be set by the caller and be valid.
    let owner_fw_boot_msg_cstr = unsafe { CStr::from_ptr(owner_fw_boot_msg) };
    let owner_fw_boot_msg_in = owner_fw_boot_msg_cstr.to_str().unwrap();

    let timeout = Duration::from_millis(timeout_ms);

    // Reset the DUT and get the UART console handle.
    transport
        .reset_target(timeout, true)
        .expect("Failed to reset the DUT.");
    let uart_console = transport
        .uart("console")
        .expect("Unable to instantiate the UART console.");

    // Wait for a successful ROM_EXT boot message.
    println!("Waiting for ROM_EXT to boot ...");
    let _ = UartConsole::wait_for(&*uart_console, r"(?:\n| )ROM_EXT[: ](.*)\r\n", timeout)
        .expect("Failed to boot the ROM_EXT.");
    println!("ROM_EXT has booted.");

    // CAUTION: This error message should match the one in
    //   @lowrisc_opentitan//sw/device/silicon_creator/lib/cert/dice_chain.c.
    let rom_ext_cert_failure_msg = r"UDS certificate not valid";
    let boot_failure_msg = r"BFV:.*\r\n";
    let boot_errors_text = format!(r"{}|{}", rom_ext_cert_failure_msg, boot_failure_msg);
    let boot_text = match owner_fw_boot_msg_in {
        "" => format!(r"(?s)({boot_errors_text})"),
        x => format!(r"(?s)({boot_errors_text}|{x})"),
    };
    println!("Boot Text: {}", boot_text);
    println!("Waiting for Owner Firmware to boot ...");
    let result = UartConsole::wait_for(&*uart_console, boot_text.as_str(), timeout);
    match result {
        Ok(captures) => {
            if captures[0] == *rom_ext_cert_failure_msg {
                println!("ROM_EXT detected invalid UDS certificate!");
                panic!("ROM_EXT detected invalid UDS certificate!");
            }
            if captures[0].starts_with("BFV:") {
                println!("Boot fault detected!");
                panic!("Boot fault detected!");
            }
        }
        Err(e) => {
            if owner_fw_boot_msg_in == "" && e.to_string().contains("Timed Out") {
                // Error message not found after timeout. This is the expected behavior.
            } else {
                // An unexpected error occurred while waiting for the console output.
                panic!("{}", e);
            }
        }
    }
    println!("Owner Firmware has booted.");
}
