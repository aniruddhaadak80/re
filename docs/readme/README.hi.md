<div align="center">

# RevLens

**किसी भी फ़ाइल के अंदर देखें: ब्राउज़र में, टर्मिनल में, या अपने AI एजेंट में।**

[English](../../README.md) · [বাংলা](README.bn.md) · हिन्दी · [中文](README.zh.md) · [日本語](README.ja.md) · [Español](README.es.md)

</div>

## RevLens क्या है

आपके पास एक फ़ाइल है और एक सवाल। क्या यह बाइनरी पैक की गई है? `main` फ़ंक्शन क्या करता है? यह APK कौन सी अनुमतियाँ माँगता है और इसे किसने साइन किया? इस Electron ऐप, PyInstaller बिल्ड या .NET असेंबली के अंदर क्या है? यह पैकेट कैप्चर किन होस्ट से बात करता है?

RevLens ऐसे सबूत के साथ जवाब देता है जिसे आप खुद जाँच सकते हैं: बाइट ऑफ़सेट, वर्चुअल एड्रेस, सेक्शन के नाम और आर्काइव पाथ। पूरा इंजन TypeScript और दो WebAssembly डिकोडर में लिखा है। कुछ भी नेटिव इंस्टॉल नहीं करना पड़ता, इसलिए वही कोड तीन जगह चलता है:

- **ब्राउज़र में**, एक Web Worker के अंदर। आपकी फ़ाइल आपकी मशीन से बाहर नहीं जाती।
- **टर्मिनल में**, `npx revlens` के रूप में, JSON, Markdown, HTML, SARIF और CycloneDX आउटपुट के साथ।
- **आपके एजेंट में**, एक MCP सर्वर के रूप में (195 MCP tools, 109 CLI commands), साथ में Claude Code और Codex के लिए तैयार स्किल और प्लगइन।

अगर आपके पास Ghidra, radare2, jadx, ILSpy, Frida या gdb है, तो RevLens उन्हें भी चलाता है। `revlens doctor` बताता है कि क्या नहीं है और उसे कैसे इंस्टॉल करें।

RevLens, morluto के [REA, Reverse Engineer Anything](https://github.com/morluto/rea) से प्रेरित है। इसे शुरू से लिखा गया है और यह REA का आधिकारिक प्रोजेक्ट नहीं है।

## यह क्या पढ़ सकता है

| क्षेत्र | फ़ॉर्मेट | आपको क्या मिलता है |
| --- | --- | --- |
| किसी भी फ़ाइल की शुरुआती जाँच | ELF, PE, Mach-O, WASM, ZIP, APK, npm tgz, ASAR, JS बंडल | फ़ॉर्मेट, हैश, सेक्शन और एंट्रॉपी, इम्पोर्ट, हार्डनिंग, पैकर, स्ट्रिंग, सीक्रेट, एंडपॉइंट, ATT&CK क्षमताएँ, yara-lite नियम, SBOM, दावों की जाँच |
| नेटिव कोड | x86, x86-64, AArch64, ARM, Thumb | फ़ंक्शन, कंट्रोल फ़्लो ग्राफ़, क्रॉस रेफ़रेंस, कॉल ग्राफ़, पढ़ने में आसान स्यूडो कोड |
| Android, Java, iOS | APK, DEX, JAR, class, IPA | मैनिफ़ेस्ट, सिग्नेचर, baksmali जैसा smali, javap आउटपुट, IPA plist और entitlements |
| मैनेज्ड रनटाइम | .NET, Python pyc, PyInstaller, Lua, BEAM, EVM | मेटाडेटा और CIL, dis आउटपुट, आर्काइव निकालना, EVM सेलेक्टर |
| JavaScript और Electron | JS, बंडल, सोर्स मैप, ASAR | डीऑब्फ़स्केशन, बंडल को मॉड्यूल में बाँटना, एंडपॉइंट, Electron सुरक्षा ऑडिट |
| नेटवर्क और डेटा | PCAP, pcapng, HAR, SQLite | फ़्लो, DNS, HTTP, TLS SNI और JA3, केवल पढ़ने वाला SELECT |
| एक्स्ट्रा | फ़र्मवेयर, GPU कोड, मॉडल फ़ाइलें, LNK, क्रैश रिपोर्ट | डीमैंगलिंग, checksec, गहरा PE और Authenticode, सबूतों का लेजर |
| बाहरी टूल | Ghidra, radare2, jadx, ILSpy, Frida, gdb और अन्य | डीकम्पाइल किया गया C, Java और C#, अनुमति के साथ डायनामिक रन |

## जल्दी शुरू करें

```bash
npx revlens setup claude-code --write   # या codex, cursor, vscode, windsurf
npx revlens doctor                      # देखें कौन से बाहरी टूल मौजूद हैं
```

`--write` के बिना setup सिर्फ़ बदलाव दिखाता है, कुछ लिखता नहीं। `--write` के साथ यह पहले पुरानी कॉन्फ़िग का बैकअप लेता है।

टर्मिनल में:

```bash
npx revlens analyze ./app.elf
npx revlens decompile ./app.elf main
npx revlens apk ./app.apk
npx revlens verify ./app.elf string=api.example.com
```

ब्राउज़र में: [aniruddhaadak80.github.io/re](https://aniruddhaadak80.github.io/re/) खोलें और फ़ाइल डालें, या [टूल्स](https://aniruddhaadak80.github.io/re/labs) पेज पर "Try a sample" दबाएँ। कुछ भी अपलोड नहीं होता।

## एजेंट इसे कैसे इस्तेमाल करते हैं

MCP सर्वर एजेंट से कहता है कि पहले `analyze_file` चलाए, फिर फ़ॉर्मेट के हिसाब से सही टूल पर जाए, और कोई भी बात कहने से पहले `verify_claim` से बाइट्स के साथ मिलान करे। पूरा तरीका [revlens-reverse-engineer स्किल](../../.agents/skills/revlens-reverse-engineer/SKILL.md) में लिखा है।

## और पढ़ें

[डॉक्स](https://aniruddhaadak80.github.io/re/docs) · [असली आउटपुट के साथ वॉकथ्रू](../showcases/README.md) · [तुलना](../comparison.md) · [लाइसेंस: MIT](../../LICENSE)

लेखक: अनिरुद्ध अदक ([GitHub](https://github.com/aniruddhaadak80))
