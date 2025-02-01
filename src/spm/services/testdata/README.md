# Test Data Generation

## `EndorseCerts` Test Data

The OpenTitan repository contains a provisioning script that can be executed
on an FPGA or silicon DUT, using the a hyperdebug interface. See  more
details here
https://github.com/lowRISC/opentitan/tree/earlgrey_1.0.0/sw/host/provisioning/orchestrator.

The orchestrator is currently available in the `earlgrey_1.0.0` branch.

The following command was used to extract the `tbs.der` from the DUT log.

```shell
export FPGA_TARGET=hyper310
bazel run \
  --//hw/bitstream/universal:env=//hw/top_earlgrey:fpga_${FPGA_TARGET}_rom_with_fake_keys \
  --//hw/bitstream/universal:otp=//hw/ip/otp_ctrl/data/earlgrey_skus/emulation:otp_img_test_unlocked0_manuf_empty \
  //sw/host/provisioning/orchestrator/src:orchestrator -- \
    --sku-config=$(pwd)/sw/host/provisioning/orchestrator/configs/skus/emulation.hjson \
    --test-unlock-token="0x11111111_11111111_11111111_11111111" \
    --test-exit-token="0x22222222_22222222_22222222_22222222" \
    --fpga=${FPGA_TARGET} \
    --non-interactive \
    --db-path=$(pwd)/provisioning.sqlite
```

The `dice_ca.pem` and `sk.pcks8.der` files were taken from the
[OpenTitan repo](https://github.com/lowRISC/opentitan/tree/earlgrey_1.0.0/sw/device/silicon_creator/manuf/keys/fake).
