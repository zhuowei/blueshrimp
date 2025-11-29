// You need Android Emulator for Android 15, "Google APIs ARM 64 v8a System Image", version 9
// frida -D emulator-5554 -n com.google.android.bluetooth -l dumpbt.js
// frida -D emulator-5554 -W com.google.android.bluetooth -l dumpbt.js
Process.attachModuleObserver({
  onAdded(module) {
    if (module.name == "libbluetooth_jni.so") {
      addHooks(module);
    }
  },
});

function addHooks(module) {
  const sym_bta_hf_client_cb_arr_init = module.base.add(0x7ad4c4 - 0x100000);
  /*
  Interceptor.attach(sym_bta_hf_client_cb_arr_init, {
    onEnter(args) {
      console.log("bta_hf_client_cb_arr_init called");
    },
  });
*/
  /*Memory.patchCode(sym_bta_hf_client_cb_arr_init, 0x4, code => {
code.writeUInt(0xdededede);
});*/

  const sym_bta_hf_client_allocate_handle = module.base.add(
    0x7ae370 - 0x100000,
  );
  /*Memory.patchCode(sym_bta_hf_client_allocate_handle, 0x4, code => {
code.writeUInt(0xdededede);
});*/
  Interceptor.attach(sym_bta_hf_client_allocate_handle, {
    onEnter(args) {
      console.log("sym_bta_hf_client_allocate_handle called");
    },
  });

  const sym_bta_hf_client_do_disc = module.base.add(0x7b2a08 - 0x100000);
  Interceptor.attach(sym_bta_hf_client_do_disc, {
    onEnter(args) {
      console.log("bta_hf_client_do_disc called");
    },
  });
  const sym_bta_hf_client_free_db = module.base.add(0x7b2cb4 - 0x100000);
  /*  Memory.patchCode(sym_bta_hf_client_free_db, 0x4, code => {
code.writeUInt(0xdededede);
});*/
  Interceptor.attach(sym_bta_hf_client_free_db, {
    onEnter(args) {
      console.log("!!! === bta_hf_client_free_db called === !!!");
    },
  });

  const sym_bta_hf_client_find_cb_by_handle = module.base.add(
    0x7adea8 - 0x100000,
  );
  Interceptor.attach(sym_bta_hf_client_find_cb_by_handle, {
    onEnter(args) {
      console.log("bta_hf_client_find_cb_by_handle called", args[0]);
    },
    onLeave(result) {
      console.log(
        "bta_hf_client_find_cb_by_handle result",
        result,
        "p_disc_db",
        result.add(0x8).readPointer(),
      );
    },
  });

  const sym_sdpu_find_ccb_by_cid = module.base.add(0xa6a394 - 0x100000);
  Interceptor.attach(sym_sdpu_find_ccb_by_cid, {
    onEnter(args) {
      console.log("sdpu_find_ccb_by_cid called", args[0]);
    },
    onLeave(result) {
      console.log(
        "sdpu_find_ccb_by_cid result",
        result,
        "p_db",
        result.isNull() ? "" : result.add(0x20).readPointer(),
      );
    },
  });

  /*
const sym_osi_malloc = module.base.add(0xc27428 - 0x100000);
Interceptor.attach(sym_osi_malloc, {
onEnter(args) {
this.size = args[0];
if (this.size.toInt32() === 0x1010) {
    console.log('osi_malloc called from:\n' +
        Thread.backtrace(this.context, Backtracer.FUZZY)
        .map(DebugSymbol.fromAddress).join('\n') + '\n');
}
},
onLeave(result) {
console.log("osi_malloc(" + this.size + ") =", result);
}
});

const sym_osi_calloc = module.base.add(0xc27514 - 0x100000);
Interceptor.attach(sym_osi_calloc, {
onEnter(args) {
this.size = args[0];
if (this.size.toInt32() === 0x1010) {
    console.log('osi_calloc called from:\n' +
        Thread.backtrace(this.context, Backtracer.FUZZY)
        .map(DebugSymbol.fromAddress).join('\n') + '\n');
}
},
onLeave(result) {
console.log("osi_calloc(" + this.size + ") =", result);
}
});
*/

  const sym_malloc =
    Process.findModuleByName("libc.so").findSymbolByName("malloc");
  Interceptor.attach(sym_malloc, {
    onEnter(args) {
      this.size = args[0];
      if (this.size.toInt32() === 0x1010) {
        console.log(
          "malloc called from:\n" +
            Thread.backtrace(this.context, Backtracer.FUZZY)
              .map(DebugSymbol.fromAddress)
              .join("\n") +
            "\n",
        );
      }
    },
    onLeave(result) {
      if (this.size.toInt32() === 0x1010) {
        console.log(
          "[" + this.threadId + "] malloc(" + this.size + ") =",
          result,
        );
      }
    },
  });

  /*const sym_free = Process.findModuleByName("libc.so").findSymbolByName("free");
Interceptor.attach(sym_free, {
onEnter(args) {
console.log("[" + this.threadId + "] free(" + args[0]+ ")");
}
});
*/

  const sym_sdp_copy_raw_data = module.base.add(0xa66c00 - 0x100000);
  Interceptor.attach(sym_sdp_copy_raw_data, {
    onEnter(args) {
      const discoveryDb = args[0].add(0x20).readPointer();
      console.log(
        "sdp_copy_raw_data",
        args[0],
        args[1],
        discoveryDb + "\n" + hexdump(discoveryDb, { length: 0x100 }),
      );
    },
  });

  console.log("hooked");
}
