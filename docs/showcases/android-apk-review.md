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
$ revlens dex-search samples/mobile/apk/com.angrydoughnuts.android.alarmclock_27.apk --query DeleteAll
class  Lcom/angrydoughnuts/android/alarmclock/AlarmClockActivity$DeleteAllConfirmation$1;
class  Lcom/angrydoughnuts/android/alarmclock/AlarmClockActivity$DeleteAllConfirmation;
string   "DeleteAllConfirmation"
string   "Lcom/angrydoughnuts/android/alarmclock/AlarmClockActivity$DeleteAllConfirmation$1;"
string   "Lcom/angrydoughnuts/android/alarmclock/AlarmClockActivity$DeleteAllConfirmation;"
```

No hardcoded URLs turned up for `http` in this app, which fits an offline alarm clock. Searching for a class name finds the confirmation dialog.

## 4. Read a class as smali

```console
$ revlens smali samples/mobile/apk/com.angrydoughnuts.android.alarmclock_27.apk --class com.angrydoughnuts.android.alarmclock.AlarmClockActivity$DeleteAllConfirmation
.class public Lcom/angrydoughnuts/android/alarmclock/AlarmClockActivity$DeleteAllConfirmation;
.super Landroid/app/DialogFragment;
.source "AlarmClockActivity.java"


# direct methods
.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/DialogFragment;-><init>()V
    return-void
.end method



# virtual methods
.method public onCreateDialog(Landroid/os/Bundle;)Landroid/app/Dialog;
    .registers 4
    new-instance p1, Landroid/app/AlertDialog$Builder;
    invoke-virtual {p0}, Lcom/angrydoughnuts/android/alarmclock/AlarmClockActivity$DeleteAllConfirmation;->getContext()Landroid/content/Context;
    move-result-object v0
    invoke-direct {p1, v0}, Landroid/app/AlertDialog$Builder;-><init>(Landroid/content/Context;)V
    const v0, 0x7f080009
    invoke-virtual {p1, v0}, Landroid/app/AlertDialog$Builder;->setTitle(I)Landroid/app/AlertDialog$Builder;
    move-result-object p1
    const v0, 0x7f08000b
    invoke-virtual {p1, v0}, Landroid/app/AlertDialog$Builder;->setMessage(I)Landroid/app/AlertDialog$Builder;
    move-result-object p1
    const v0, 0x7f080005
    const/4 v1, 0x0
    invoke-virtual {p1, v0, v1}, Landroid/app/AlertDialog$Builder;->setNegativeButton(ILandroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;
    move-result-object p1
    new-instance v0, Lcom/angrydoughnuts/android/alarmclock/AlarmClockActivity$DeleteAllConfirmation$1;
    invoke-direct {v0, p0}, Lcom/angrydoughnuts/android/alarmclock/AlarmClockActivity$DeleteAllConfirmation$1;-><init>(Lcom/angrydoughnuts/android/alarmclock/AlarmClockActivity$DeleteAllConfirmation;)V
    const p0, 0x7f08002a
    invoke-virtual {p1, p0, v0}, Landroid/app/AlertDialog$Builder;->setPositiveButton(ILandroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;
    move-result-object p0
    invoke-virtual {p0}, Landroid/app/AlertDialog$Builder;->create()Landroid/app/AlertDialog;
    move-result-object p0
    return-object p0
.end method
```

The smali output matches baksmali line for line on the test corpus. For Java source, install jadx and run `revlens bridge jadx_decompile samples/mobile/apk/com.angrydoughnuts.android.alarmclock_27.apk`.
