---
title: "Showcase: review an Android app before you install it"
description: Read the manifest, signatures, permissions, exported components and network calls of a real F-Droid APK without Java or the Android SDK.
order: 2
---

# Showcase: review an Android app before you install it

The file is `samples/mobile/apk/com.angrydoughnuts.android.alarmclock_27.apk`, the Alarm Clock app from F-Droid. The questions: what does it ask for, who signed it, and what does its code reach out to?

## 1. The one shot report

```console
$ revlens apk samples/mobile/apk/com.angrydoughnuts.android.alarmclock_27.apk
com.angrydoughnuts.android.alarmclock 2.13 (27)  minSdk 33  targetSdk 36  apk
label: Alarm Klock   launcher: com.angrydoughnuts.android.alarmclock.AlarmClockActivity
signing: v1=true v2=true v3=true  cert sha256 b4582f0386a2ac6f150c7ca782df4040744ee2b6d33ecfbe4f6488e326288e49
dex: classes.dex v039 111 classes
abis: none   frameworks: none detected
libraries: none detected
permissions (10): WAKE_LOCK, READ_MEDIA_AUDIO*, RECEIVE_BOOT_COMPLETED, VIBRATE, FOREGROUND_SERVICE, FOREGROUND_SERVICE_MEDIA_PLAYBACK, USE_FULL_SCREEN_INTENT, SCHEDULE_EXACT_ALARM, POST_NOTIFICATIONS*, REQUEST_IGNORE_BATTERY_OPTIMIZATIONS

findings (1):
  [info] 3 sensitive permission(s) requested
```


## 2. Who signed it

```console
$ revlens apksig samples/mobile/apk/com.angrydoughnuts.android.alarmclock_27.apk
v1: true  v2: true  v3: true  v3.1: false  source stamp: false
v1 META-INF/EC9152AF.RSA
  subject CN=FDroid, OU=FDroid, O=fdroid.org, L=ORG, ST=ORG, C=UK
  issuer  CN=FDroid, OU=FDroid, O=fdroid.org, L=ORG, ST=ORG, C=UK
  serial  1305797533
  sha256  b4582f0386a2ac6f150c7ca782df4040744ee2b6d33ecfbe4f6488e326288e49
  valid   2011-05-19T09:32:13Z .. 2038-10-04T09:32:13Z
v2 signer sha256 b4582f0386a2ac6f150c7ca782df4040744ee2b6d33ecfbe4f6488e326288e49
v3 signer sha256 b4582f0386a2ac6f150c7ca782df4040744ee2b6d33ecfbe4f6488e326288e49 sdk 24..2147483647
```

RevLens reads the v1 JAR signature and the APK Signing Block. It reports what is present and the certificate digests. It does not verify the signatures cryptographically.

## 3. Search the code

```console
$ revlens dex-search samples/mobile/apk/com.angrydoughnuts.android.alarmclock_27.apk --query http
no matches
```


## 4. Read a method as smali

```console
$ revlens dex samples/mobile/apk/com.angrydoughnuts.android.alarmclock_27.apk --filter AlarmClockActivity
classes.dex  dex 039  111 classes  822 methods  1203 strings
libraries: none
obfuscation: unlikely

com.angrydoughnuts.android.alarmclock.AlarmClockActivity$1  2m 1f  extends Ljava/lang/Object;
com.angrydoughnuts.android.alarmclock.AlarmClockActivity$2  2m 1f  extends Ljava/lang/Object;
com.angrydoughnuts.android.alarmclock.AlarmClockActivity$3  2m 1f  extends Landroid/widget/ResourceCursorAdapter;
com.angrydoughnuts.android.alarmclock.AlarmClockActivity$4  2m 1f  extends Ljava/lang/Object;
com.angrydoughnuts.android.alarmclock.AlarmClockActivity$5  2m 1f  extends Ljava/lang/Object;
com.angrydoughnuts.android.alarmclock.AlarmClockActivity$6  5m 2f  extends Ljava/lang/Object;
com.angrydoughnuts.android.alarmclock.AlarmClockActivity$7  2m 2f  extends Ljava/lang/Object;
com.angrydoughnuts.android.alarmclock.AlarmClockActivity$8  2m 1f  extends Ljava/lang/Object;
com.angrydoughnuts.android.alarmclock.AlarmClockActivity$9  2m 1f  extends Ljava/lang/Object;
com.angrydoughnuts.android.alarmclock.AlarmClockActivity$DeleteAllConfirmation$1  2m 1f  extends Ljava/lang/Object;
com.angrydoughnuts.android.alarmclock.AlarmClockActivity$DeleteAllConfirmation  2m 0f  extends Landroid/app/DialogFragment;
... (2 more lines)
```

The smali output matches baksmali line for line on the test corpus. For Java source, install jadx and run `revlens bridge jadx_decompile samples/mobile/apk/com.angrydoughnuts.android.alarmclock_27.apk`.
