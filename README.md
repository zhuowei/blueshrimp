Learning how to use Bumble to connect to Bluetooth headphones.

To make Android Emulator emulate a Bluetooth headphone:

Start a local Android Emulator for Android 15 in Android Studio.

```
adb root
adb shell
setprop bluetooth.profile.hfp.hf.enabled true
am force-stop com.google.android.bluetooth
```

Then

```
python3 -m venv env
. env/bin/activate
pip install bumble
python3 blueshrimp.py
```
