<div align="center">

# RevLens

**Mira dentro de cualquier archivo: en tu navegador, en tu terminal o en tu agente de IA.**

[English](../../README.md) · [বাংলা](README.bn.md) · [हिन्दी](README.hi.md) · [中文](README.zh.md) · [日本語](README.ja.md) · Español

</div>

## Qué es RevLens

Tienes un archivo y una pregunta. ¿Este binario está empaquetado? ¿Qué hace la función `main`? ¿Qué permisos pide este APK y quién lo firmó? ¿Qué hay dentro de esta app de Electron, de este ejecutable de PyInstaller o de este ensamblado .NET? ¿Con qué servidores habla esta captura de paquetes?

RevLens responde con pruebas que puedes comprobar tú mismo: desplazamientos en bytes, direcciones virtuales, nombres de secciones y rutas dentro de archivos comprimidos. Todo el motor está escrito en TypeScript con dos decodificadores en WebAssembly. No hace falta instalar nada nativo, así que el mismo código funciona en tres sitios:

- **En el navegador**, dentro de un Web Worker. Tu archivo nunca sale de tu equipo.
- **En la terminal**, como `npx revlens`, con salida en JSON, Markdown, HTML, SARIF y CycloneDX.
- **En tu agente**, como servidor MCP (203 herramientas MCP, 117 comandos de CLI), con una skill y plugins listos para Claude Code y Codex.

Si tienes Ghidra, radare2, jadx, ILSpy, Frida o gdb, RevLens también los usa. `revlens doctor` te dice qué falta y cómo instalarlo.

RevLens está inspirado en [REA, Reverse Engineer Anything](https://github.com/morluto/rea) de morluto. Está escrito desde cero y no es un proyecto oficial de REA.

## Qué puede leer

| Área | Formatos | Qué obtienes |
| --- | --- | --- |
| Primer vistazo a cualquier archivo | ELF, PE, Mach-O, WASM, ZIP, APK, npm tgz, ASAR, bundles de JS | Formato, hashes, secciones y entropía, importaciones, protecciones, empaquetadores, cadenas, secretos, endpoints, capacidades ATT&CK, reglas yara-lite, SBOM, verificación de afirmaciones |
| Código nativo | x86, x86-64, AArch64, ARM, Thumb | Funciones, grafos de flujo de control, referencias cruzadas, grafo de llamadas, pseudocódigo legible, flujo de valores, tablas de saltos y vtables resueltas, emparejamiento de funciones entre versiones |
| Android, Java, iOS | APK, DEX, JAR, class, IPA | Manifiesto, firmas, smali al estilo de baksmali, salida al estilo de javap, plist y entitlements de IPA, grafo de componentes de la app, mapa JNI, diferencias de miembros |
| Runtimes gestionados | .NET, Python pyc, PyInstaller, Lua, BEAM, EVM | Metadatos y CIL, salida de dis, extracción de archivos, selectores EVM |
| JavaScript y Electron | JS, bundles, source maps, ASAR, páginas en vivo | Desofuscación, división del bundle en módulos, endpoints, auditoría de seguridad de Electron, escenarios de navegador con aserciones, comparación de dos ejecuciones |
| Red y datos | PCAP, pcapng, HAR, SQLite | Flujos, DNS, HTTP, TLS SNI y JA3, SELECT de solo lectura |
| Extras | Firmware, código de GPU, archivos de modelos, LNK, informes de fallos, registro de Windows, Prefetch, Jump Lists, nibs, Assets.car, wxapkg, UnityFS | Demangling de C++, Rust, MSVC y Swift, checksec, análisis profundo de PE y Authenticode, contratos de API protobuf, OpenAPI y GraphQL, registro de pruebas |
| Escritorio | Procesos, apps instaladas, interfaz nativa | Módulos, archivos y sockets abiertos, comparación de instantáneas, detección de apps Electron, árbol de accesibilidad |
| Herramientas externas | Ghidra, radare2, jadx, ILSpy, Frida, gdb y más | C, Java y C# descompilados, ejecución dinámica con tu permiso, sesiones de depuración que siguen abiertas, nombres que se escriben de vuelta en Ghidra, IDA y radare2 |

## Empezar rápido

```bash
npx revlens setup claude-code --write   # o codex, cursor, vscode, windsurf
npx revlens doctor                      # mira qué herramientas externas tienes
```

Sin `--write`, setup solo muestra los cambios y no escribe nada. Con `--write`, primero hace una copia de seguridad de la configuración que ya tenías.

En la terminal:

```bash
npx revlens analyze ./app.elf
npx revlens decompile ./app.elf main
npx revlens apk ./app.apk
npx revlens verify ./app.elf string=api.example.com
```

En el navegador: abre [aniruddhaadak80.github.io/re](https://aniruddhaadak80.github.io/re/) y suelta un archivo, o pulsa "Try a sample" en la página de [herramientas](https://aniruddhaadak80.github.io/re/labs). No se sube nada.

## Cómo lo usan los agentes

El servidor MCP le indica al agente que empiece con `analyze_file`, que pase después a la herramienta adecuada para el formato y que compruebe cualquier afirmación contra los bytes con `verify_claim` antes de darla por buena. El método completo está en la [skill revlens-reverse-engineer](../../.agents/skills/revlens-reverse-engineer/SKILL.md).

## Para leer más

[Documentación](https://aniruddhaadak80.github.io/re/docs) · [Recorridos con salida real](../showcases/README.md) · [Comparación](../comparison.md) · [Licencia: MIT](../../LICENSE)

El demangler de Swift de `@revlens/extras` es un port del código del proyecto Swift (Apple Inc. y los autores del proyecto Swift) y mantiene la Apache License 2.0 con Runtime Library Exception. Más detalles en [NOTICE](../../NOTICE).

Autor: Aniruddha Adak ([GitHub](https://github.com/aniruddhaadak80))
