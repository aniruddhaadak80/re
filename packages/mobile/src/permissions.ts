// Protection levels and short risk notes for Android platform permissions.
// Levels follow the platform AndroidManifest (core/res) as documented on developer.android.com.

export type ProtectionLevel = 'normal' | 'dangerous' | 'signature' | 'special' | 'unknown';

export interface PermissionInfo {
  level: ProtectionLevel;
  group?: string;
  note: string;
}

const D = (group: string, note: string): PermissionInfo => ({ level: 'dangerous', group, note });
const S = (note: string): PermissionInfo => ({ level: 'special', note });
const SIG = (note: string): PermissionInfo => ({ level: 'signature', note });
const N = (note: string): PermissionInfo => ({ level: 'normal', note });

export const PERMISSIONS: Record<string, PermissionInfo> = {
  READ_CALENDAR: D('CALENDAR', 'reads calendar events and attendees'),
  WRITE_CALENDAR: D('CALENDAR', 'adds or changes calendar events'),
  CAMERA: D('CAMERA', 'takes photos and video'),
  READ_CONTACTS: D('CONTACTS', 'reads the address book'),
  WRITE_CONTACTS: D('CONTACTS', 'changes the address book'),
  GET_ACCOUNTS: D('CONTACTS', 'lists accounts on the device'),
  ACCESS_FINE_LOCATION: D('LOCATION', 'precise GPS location'),
  ACCESS_COARSE_LOCATION: D('LOCATION', 'approximate network location'),
  ACCESS_BACKGROUND_LOCATION: D('LOCATION', 'location while the app is in the background'),
  ACCESS_MEDIA_LOCATION: D('STORAGE', 'location metadata inside photos'),
  RECORD_AUDIO: D('MICROPHONE', 'records audio from the microphone'),
  READ_PHONE_STATE: D('PHONE', 'reads phone number, IMEI style identifiers and call state'),
  READ_PHONE_NUMBERS: D('PHONE', 'reads the device phone numbers'),
  CALL_PHONE: D('PHONE', 'places calls without the dialer'),
  ANSWER_PHONE_CALLS: D('PHONE', 'answers incoming calls'),
  READ_CALL_LOG: D('CALL_LOG', 'reads call history'),
  WRITE_CALL_LOG: D('CALL_LOG', 'changes call history'),
  PROCESS_OUTGOING_CALLS: D('CALL_LOG', 'sees and redirects outgoing calls'),
  ADD_VOICEMAIL: D('PHONE', 'adds voicemail'),
  USE_SIP: D('PHONE', 'makes SIP calls'),
  ACCEPT_HANDOVER: D('PHONE', 'continues a call started in another app'),
  BODY_SENSORS: D('SENSORS', 'reads heart rate and other body sensors'),
  BODY_SENSORS_BACKGROUND: D('SENSORS', 'body sensors in the background'),
  ACTIVITY_RECOGNITION: D('ACTIVITY_RECOGNITION', 'detects walking, driving and other activity'),
  SEND_SMS: D('SMS', 'sends SMS, can cost money'),
  RECEIVE_SMS: D('SMS', 'reads incoming SMS, often used to grab one time codes'),
  READ_SMS: D('SMS', 'reads stored SMS'),
  RECEIVE_WAP_PUSH: D('SMS', 'receives WAP push messages'),
  RECEIVE_MMS: D('SMS', 'receives MMS'),
  READ_CELL_BROADCASTS: D('SMS', 'reads cell broadcast messages'),
  READ_EXTERNAL_STORAGE: D('STORAGE', 'reads shared storage'),
  WRITE_EXTERNAL_STORAGE: D('STORAGE', 'writes shared storage'),
  READ_MEDIA_IMAGES: D('READ_MEDIA_VISUAL', 'reads photos'),
  READ_MEDIA_VIDEO: D('READ_MEDIA_VISUAL', 'reads videos'),
  READ_MEDIA_AUDIO: D('READ_MEDIA_AURAL', 'reads audio files'),
  READ_MEDIA_VISUAL_USER_SELECTED: D('READ_MEDIA_VISUAL', 'reads photos the user picked'),
  BLUETOOTH_SCAN: D('NEARBY_DEVICES', 'scans for Bluetooth devices, can infer location'),
  BLUETOOTH_CONNECT: D('NEARBY_DEVICES', 'connects to paired Bluetooth devices'),
  BLUETOOTH_ADVERTISE: D('NEARBY_DEVICES', 'advertises to nearby Bluetooth devices'),
  UWB_RANGING: D('NEARBY_DEVICES', 'ultra wideband ranging'),
  NEARBY_WIFI_DEVICES: D('NEARBY_DEVICES', 'finds nearby Wi-Fi devices'),
  POST_NOTIFICATIONS: D('NOTIFICATIONS', 'shows notifications'),
  SYSTEM_ALERT_WINDOW: S('draws over other apps, used in overlay and tapjacking attacks'),
  WRITE_SETTINGS: S('changes system settings'),
  MANAGE_EXTERNAL_STORAGE: S('full access to all shared files'),
  REQUEST_INSTALL_PACKAGES: S('can ask to install other APKs'),
  PACKAGE_USAGE_STATS: S('reads which apps the user runs and for how long'),
  BIND_ACCESSIBILITY_SERVICE: SIG('accessibility service, can read the screen and act for the user, common in banking malware'),
  BIND_NOTIFICATION_LISTENER_SERVICE: SIG('reads every notification, including one time codes'),
  BIND_DEVICE_ADMIN: SIG('device admin, can lock or wipe the device and resist uninstall'),
  BIND_VPN_SERVICE: SIG('VPN service, sees all network traffic'),
  BIND_INPUT_METHOD: SIG('keyboard, sees everything typed'),
  REQUEST_IGNORE_BATTERY_OPTIMIZATIONS: N('asks to skip battery limits so it keeps running'),
  SCHEDULE_EXACT_ALARM: S('exact alarms'),
  USE_EXACT_ALARM: N('exact alarms for clock and calendar apps'),
  QUERY_ALL_PACKAGES: N('lists every installed app'),
  READ_PRIVILEGED_PHONE_STATE: SIG('privileged phone identifiers'),
  INSTALL_PACKAGES: SIG('silently installs apps (system only)'),
  DELETE_PACKAGES: SIG('uninstalls apps (system only)'),
  READ_LOGS: SIG('reads system logs'),
  WRITE_SECURE_SETTINGS: SIG('changes secure settings'),
  MOUNT_UNMOUNT_FILESYSTEMS: SIG('mounts file systems'),
  INTERNET: N('opens network sockets'),
  ACCESS_NETWORK_STATE: N('reads network state'),
  ACCESS_WIFI_STATE: N('reads Wi-Fi state'),
  CHANGE_WIFI_STATE: N('changes Wi-Fi state'),
  WAKE_LOCK: N('keeps the device awake'),
  VIBRATE: N('vibrates'),
  RECEIVE_BOOT_COMPLETED: N('starts at boot, a common persistence step'),
  FOREGROUND_SERVICE: N('runs foreground services'),
  BLUETOOTH: N('legacy Bluetooth access'),
  BLUETOOTH_ADMIN: N('legacy Bluetooth admin'),
  NFC: N('uses NFC'),
  USE_BIOMETRIC: N('uses biometric prompt'),
  USE_FINGERPRINT: N('uses fingerprint hardware'),
  DISABLE_KEYGUARD: N('disables the lock screen'),
  KILL_BACKGROUND_PROCESSES: N('kills other apps background processes'),
  SET_ALARM: N('sets alarms in the clock app'),
  CHANGE_NETWORK_STATE: N('changes network connectivity'),
  EXPAND_STATUS_BAR: N('expands the status bar'),
  GET_TASKS: N('legacy: lists running tasks'),
  REORDER_TASKS: N('reorders tasks'),
  USE_FULL_SCREEN_INTENT: N('full screen notifications'),
};

/** Look up a permission name, with or without the android.permission. prefix. */
export function permissionInfo(name: string): PermissionInfo & { platform: boolean } {
  const short = name.startsWith('android.permission.') ? name.slice('android.permission.'.length) : undefined;
  if (short !== undefined) {
    const p = PERMISSIONS[short];
    if (p) return { ...p, platform: true };
    if (short.startsWith('FOREGROUND_SERVICE_')) return { level: 'normal', note: `foreground service type ${short.slice(19).toLowerCase()}`, platform: true };
    return { level: 'unknown', note: 'platform permission not in the RevLens table', platform: true };
  }
  if (name === 'com.android.alarm.permission.SET_ALARM') return { ...(PERMISSIONS.SET_ALARM as PermissionInfo), platform: true };
  return { level: 'unknown', note: 'custom or vendor permission', platform: false };
}
