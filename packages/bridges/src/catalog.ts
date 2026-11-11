// What each external tool is, what RevLens can do with it, and how to install it on each OS.
// Pure data, safe for browsers. Package ids were checked against the Homebrew API, the Scoop
// Main/Extras/Java buckets, the Chocolatey community feed, winget-pkgs manifests and the
// Debian 13 archive on 2026-11-11.
import type { InstallInfo, InstallMethods, Platform, ToolId } from './types.js';

export interface ToolMeta {
  id: ToolId;
  name: string;
  description: string;
  capabilities: string[];
  requires: ToolId[];
  install: InstallInfo;
}

const r2Script = 'git clone --depth 1 https://github.com/radareorg/radare2 && radare2/sys/install.sh';

export const TOOL_META: Record<ToolId, ToolMeta> = {
  radare2: {
    id: 'radare2', name: 'radare2',
    description: 'Scriptable disassembler and analysis framework. With the r2ghidra plugin it also decompiles to C.',
    capabilities: ['functions', 'disassemble', 'decompile', 'xrefs', 'strings', 'imports', 'binary-info'],
    requires: [],
    install: {
      homepage: 'https://github.com/radareorg/radare2', license: 'LGPL-3.0',
      linux: { script: r2Script, url: 'https://github.com/radareorg/radare2/releases', note: 'Release .deb files exist for amd64 and arm64. Decompiler plugin: r2pm -ci r2ghidra' },
      darwin: { brew: 'brew install radare2', note: 'Decompiler plugin: r2pm -ci r2ghidra' },
      win32: { scoop: 'scoop install radare2', choco: 'choco install radare2', url: 'https://github.com/radareorg/radare2/releases' },
    },
  },
  rizin: {
    id: 'rizin', name: 'rizin',
    description: 'radare2 fork with a stable command set. rz-ghidra adds decompilation.',
    capabilities: ['functions', 'disassemble', 'decompile', 'xrefs', 'strings', 'imports', 'binary-info'],
    requires: [],
    install: {
      homepage: 'https://rizin.re', license: 'LGPL-3.0',
      linux: { url: 'https://github.com/rizinorg/rizin/releases', note: 'A static x86_64 build is published on the releases page. Build from source on other CPUs.' },
      darwin: { brew: 'brew install rizin' },
      win32: { winget: 'winget install Rizin.Rizin', scoop: 'scoop install rizin', choco: 'choco install rizin' },
    },
  },
  cutter: {
    id: 'cutter', name: 'Cutter',
    description: 'Graphical front end for rizin. Detected only, RevLens drives rizin directly.',
    capabilities: ['gui'],
    requires: [],
    install: {
      homepage: 'https://cutter.re', license: 'GPL-3.0',
      linux: { url: 'https://github.com/rizinorg/cutter/releases', note: 'AppImage download' },
      darwin: { brew: 'brew install --cask cutter' },
      win32: { scoop: 'scoop bucket add extras; scoop install cutter', choco: 'choco install cutter' },
    },
  },
  ghidra: {
    id: 'ghidra', name: 'Ghidra (headless)',
    description: 'NSA reverse engineering suite. RevLens runs analyzeHeadless with its own export script to list functions and decompile to C.',
    capabilities: ['functions', 'decompile', 'binary-info'],
    requires: ['java'],
    install: {
      homepage: 'https://github.com/NationalSecurityAgency/ghidra', license: 'Apache-2.0',
      linux: { url: 'https://github.com/NationalSecurityAgency/ghidra/releases', note: 'Unzip, then set GHIDRA_INSTALL_DIR. Needs the JDK version named in Ghidra/application.properties (JDK 25 for Ghidra 12.2, JDK 21 for 11.x). On arm64 Linux build the decompiler once: make -C Ghidra/Features/Decompiler/src/decompile/cpp ghidra_opt.' },
      darwin: { brew: 'brew install ghidra', url: 'https://github.com/NationalSecurityAgency/ghidra/releases' },
      win32: { scoop: 'scoop bucket add extras; scoop install ghidra', choco: 'choco install ghidra', url: 'https://github.com/NationalSecurityAgency/ghidra/releases' },
    },
  },
  java: {
    id: 'java', name: 'Java (JDK)',
    description: 'Needed by Ghidra, jadx and apktool.',
    capabilities: ['jvm'],
    requires: [],
    install: {
      homepage: 'https://adoptium.net', license: 'GPL-2.0-with-classpath-exception',
      linux: { apt: 'sudo apt-get install -y openjdk-21-jdk', url: 'https://adoptium.net/temurin/releases/', note: 'Ghidra 12 needs JDK 25: sudo apt-get install -y openjdk-25-jdk where available, or the Temurin 25 tarball.' },
      darwin: { brew: 'brew install --cask temurin@25' },
      win32: { winget: 'winget install EclipseAdoptium.Temurin.25.JDK', scoop: 'scoop bucket add java; scoop install temurin25-jdk', choco: 'choco install temurin25' },
    },
  },
  jadx: {
    id: 'jadx', name: 'jadx',
    description: 'Dex and Java bytecode to Java source decompiler for APK, DEX, JAR, AAR and class files.',
    capabilities: ['java-decompile', 'apk-decompile', 'source-search'],
    requires: ['java'],
    install: {
      homepage: 'https://github.com/skylot/jadx', license: 'Apache-2.0',
      linux: { url: 'https://github.com/skylot/jadx/releases', note: 'Unzip jadx-<version>.zip and put bin/ on PATH or set JADX_HOME.' },
      darwin: { brew: 'brew install jadx' },
      win32: { scoop: 'scoop bucket add extras; scoop install jadx', choco: 'choco install jadx' },
    },
  },
  apktool: {
    id: 'apktool', name: 'Apktool',
    description: 'Decodes APK resources, AndroidManifest.xml and smali.',
    capabilities: ['apk-decode', 'smali'],
    requires: ['java'],
    install: {
      homepage: 'https://apktool.org', license: 'Apache-2.0',
      linux: { apt: 'sudo apt-get install -y apktool', url: 'https://apktool.org/docs/install' },
      darwin: { brew: 'brew install apktool' },
      win32: { scoop: 'scoop install apktool', choco: 'choco install apktool' },
    },
  },
  ilspy: {
    id: 'ilspy', name: 'ILSpy command line (ilspycmd)',
    description: '.NET assembly to C# decompiler.',
    capabilities: ['dotnet-decompile', 'dotnet-types'],
    requires: ['dotnet'],
    install: {
      homepage: 'https://github.com/icsharpcode/ILSpy', license: 'MIT',
      linux: { dotnet: 'dotnet tool install --global ilspycmd' },
      darwin: { dotnet: 'dotnet tool install --global ilspycmd' },
      win32: { dotnet: 'dotnet tool install --global ilspycmd', winget: 'winget install icsharpcode.ILSpy', note: 'The winget and scoop packages are the GUI. RevLens needs ilspycmd.' },
    },
  },
  dotnet: {
    id: 'dotnet', name: '.NET SDK',
    description: 'Needed to install and run ilspycmd.',
    capabilities: ['dotnet-runtime'],
    requires: [],
    install: {
      homepage: 'https://dotnet.microsoft.com/download', license: 'MIT',
      linux: { script: 'curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 8.0', url: 'https://learn.microsoft.com/dotnet/core/install/linux' },
      darwin: { brew: 'brew install --cask dotnet-sdk' },
      win32: { winget: 'winget install Microsoft.DotNet.SDK.8', scoop: 'scoop install dotnet-sdk', choco: 'choco install dotnet-8.0-sdk' },
    },
  },
  frida: {
    id: 'frida', name: 'Frida tools',
    description: 'Dynamic instrumentation: list processes and devices, spawn or attach and inject hook scripts.',
    capabilities: ['processes', 'devices', 'hook', 'trace'],
    requires: [],
    install: {
      homepage: 'https://frida.re', license: 'wxWindows-3.1',
      linux: { pip: 'pipx install frida-tools' },
      darwin: { pip: 'pipx install frida-tools' },
      win32: { pip: 'pipx install frida-tools' },
    },
  },
  gdb: {
    id: 'gdb', name: 'GDB',
    description: 'GNU debugger, used in batch mode for breakpoints, registers, backtraces and memory dumps.',
    capabilities: ['debug', 'registers', 'backtrace'],
    requires: [],
    install: {
      homepage: 'https://www.sourceware.org/gdb/', license: 'GPL-3.0',
      linux: { apt: 'sudo apt-get install -y gdb' },
      darwin: { brew: 'brew install gdb', note: 'Intel Macs only, and the binary must be code signed. Use lldb on Apple silicon.' },
      win32: { scoop: 'scoop install gdb' },
    },
  },
  lldb: {
    id: 'lldb', name: 'LLDB',
    description: 'LLVM debugger, used in batch mode as the gdb alternative.',
    capabilities: ['debug', 'registers', 'backtrace'],
    requires: [],
    install: {
      homepage: 'https://lldb.llvm.org', license: 'Apache-2.0-with-LLVM-exception',
      linux: { apt: 'sudo apt-get install -y lldb' },
      darwin: { script: 'xcode-select --install', brew: 'brew install llvm' },
      win32: { winget: 'winget install LLVM.LLVM', scoop: 'scoop install llvm', choco: 'choco install llvm' },
    },
  },
  objdump: {
    id: 'objdump', name: 'GNU objdump',
    description: 'Fallback disassembler, section and symbol lister from binutils.',
    capabilities: ['disassemble', 'sections', 'symbols'],
    requires: [],
    install: {
      homepage: 'https://www.gnu.org/software/binutils/', license: 'GPL-3.0',
      linux: { apt: 'sudo apt-get install -y binutils' },
      darwin: { brew: 'brew install binutils' },
      win32: { scoop: 'scoop install binutils', choco: 'choco install mingw' },
    },
  },
  'llvm-objdump': {
    id: 'llvm-objdump', name: 'llvm-objdump',
    description: 'LLVM disassembler with the same output style as GNU objdump. Handles Mach-O and PE well.',
    capabilities: ['disassemble', 'sections', 'symbols'],
    requires: [],
    install: {
      homepage: 'https://llvm.org', license: 'Apache-2.0-with-LLVM-exception',
      linux: { apt: 'sudo apt-get install -y llvm' },
      darwin: { script: 'xcode-select --install', brew: 'brew install llvm' },
      win32: { winget: 'winget install LLVM.LLVM', scoop: 'scoop install llvm', choco: 'choco install llvm' },
    },
  },
  binwalk: {
    id: 'binwalk', name: 'binwalk',
    description: 'Firmware signature scanner and carver.',
    capabilities: ['firmware-scan', 'carve'],
    requires: [],
    install: {
      homepage: 'https://github.com/ReFirmLabs/binwalk', license: 'MIT',
      linux: { apt: 'sudo apt-get install -y binwalk', cargo: 'cargo install binwalk' },
      darwin: { brew: 'brew install binwalk' },
      win32: { cargo: 'cargo install binwalk', note: 'binwalk v3 is a Rust tool. Build it with cargo or use WSL.' },
    },
  },
  adb: {
    id: 'adb', name: 'Android Debug Bridge',
    description: 'Talks to Android devices and emulators: devices, packages, pull APKs, logcat.',
    capabilities: ['android-devices', 'android-packages', 'pull-apk', 'logcat'],
    requires: [],
    install: {
      homepage: 'https://developer.android.com/tools/releases/platform-tools', license: 'Apache-2.0',
      linux: { apt: 'sudo apt-get install -y adb' },
      darwin: { brew: 'brew install --cask android-platform-tools' },
      win32: { winget: 'winget install Google.PlatformTools', scoop: 'scoop install adb', choco: 'choco install adb' },
    },
  },
  ida: {
    id: 'ida', name: 'IDA Pro / IDA Free (idat)',
    description: 'Commercial disassembler. RevLens runs idat in batch mode with an IDAPython export script.',
    capabilities: ['functions', 'decompile'],
    requires: [],
    install: {
      homepage: 'https://hex-rays.com/ida-free', license: 'proprietary',
      linux: { url: 'https://hex-rays.com/ida-free', note: 'Set IDADIR to the install folder.' },
      darwin: { url: 'https://hex-rays.com/ida-free', note: 'Set IDADIR to the folder holding idat.' },
      win32: { url: 'https://hex-rays.com/ida-free', note: 'Set IDADIR to the install folder.' },
    },
  },
  binja: {
    id: 'binja', name: 'Binary Ninja (headless)',
    description: 'Commercial analysis platform. Detected, and a Python script can be run with its headless API when the license allows it.',
    capabilities: ['run-script'],
    requires: [],
    install: {
      homepage: 'https://binary.ninja', license: 'proprietary',
      linux: { url: 'https://binary.ninja/free/', note: 'Headless use needs a Commercial or Ultimate license. Set BN_INSTALL_DIR.' },
      darwin: { brew: 'brew install --cask binary-ninja-free', note: 'Headless use needs a Commercial or Ultimate license.' },
      win32: { url: 'https://binary.ninja/free/', note: 'Headless use needs a Commercial or Ultimate license.' },
    },
  },
  hopper: {
    id: 'hopper', name: 'Hopper Disassembler',
    description: 'Commercial disassembler for macOS and Linux. Detected only.',
    capabilities: ['gui'],
    requires: [],
    install: {
      homepage: 'https://www.hopperapp.com', license: 'proprietary',
      linux: { url: 'https://www.hopperapp.com/download.html' },
      darwin: { brew: 'brew install --cask hopper-disassembler' },
      win32: { note: 'Hopper is not available on Windows.' },
    },
  },
};

export const TOOL_IDS = Object.keys(TOOL_META) as ToolId[];

export function currentPlatform(p: string = typeof process !== 'undefined' ? process.platform : 'linux'): Platform {
  return p === 'darwin' ? 'darwin' : p === 'win32' ? 'win32' : 'linux';
}

/** Install commands for one tool on one OS, with its homepage. */
export function installFor(id: ToolId, platform: Platform = currentPlatform()): InstallMethods & { homepage: string } {
  const meta = TOOL_META[id];
  return { homepage: meta.install.homepage, ...meta.install[platform] };
}
