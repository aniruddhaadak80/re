"""Builds the data fixtures for @revlens/extras with reference writers.
gguf-py (ggml-org, MIT), safetensors (HF, Apache-2.0), numpy (BSD), pylnk3 (LGPL, used only
to write the fixture, not shipped), intelhex (BSD), fdt (Apache-2.0), uboot (BSD-3)."""
import numpy as np, gguf, pylnk3, intelhex, fdt, os
from safetensors.numpy import save_file
os.chdir(os.path.join(os.path.dirname(__file__), '..'))
# GGUF
w = gguf.GGUFWriter('tiny.gguf', 'llama')
w.add_name('revlens-tiny'); w.add_context_length(128); w.add_embedding_length(8); w.add_block_count(1)
w.add_head_count(2); w.add_layer_norm_rms_eps(1e-5); w.add_file_type(1)
w.add_tokenizer_model('gpt2'); w.add_token_list(['<s>', '</s>', 'a', 'b'])
w.add_tensor('token_embd.weight', np.arange(32, dtype=np.float32).reshape(4, 8))
w.add_tensor('blk.0.attn_q.weight', np.ones((8, 8), dtype=np.float16))
w.add_tensor('output_norm.weight', np.ones(8, dtype=np.float32))
w.write_header_to_file(); w.write_kv_data_to_file(); w.write_tensors_to_file(); w.close()
# safetensors
save_file({'embed.weight': np.zeros((4, 8), dtype=np.float32), 'head.bias': np.zeros(3, dtype=np.float16), 'ids': np.arange(5, dtype=np.int64)}, 'tiny.safetensors', metadata={'format': 'np', 'origin': 'revlens'})
np.save('tiny.npy', np.zeros((2, 3, 4), dtype='<f8'))
# LNK
lnk = pylnk3.for_file(r'C:\Windows\System32\notepad.exe', 'notepad.lnk', arguments='C:\\Users\\Public\\readme.txt', description='Open the readme', icon_file=r'C:\Windows\System32\notepad.exe', icon_index=0, work_dir=r'C:\Users\Public')
# Intel HEX
ih = intelhex.IntelHex()
for i in range(300): ih[0x08000000 + i] = (i * 7) & 0xff
for i in range(16): ih[0x08010000 + i] = i
ih.start_addr = {'EIP': 0x08000101}
ih.write_hex_file('fw.hex')
# DTB
t = fdt.FDT(); t.header.version = 17
root = t.root_node
root.append(fdt.PropStrings('compatible', 'revlens,test-board', 'simple-bus'))
root.append(fdt.PropWords('#address-cells', 1)); root.append(fdt.PropWords('#size-cells', 1))
root.append(fdt.PropStrings('model', 'RevLens Test Board'))
cpus = fdt.Node('cpus'); c0 = fdt.Node('cpu@0'); c0.append(fdt.PropStrings('compatible', 'arm,cortex-a53')); c0.append(fdt.PropWords('reg', 0)); cpus.append(c0); root.append(cpus)
mem = fdt.Node('memory@80000000'); mem.append(fdt.PropStrings('device_type', 'memory')); mem.append(fdt.PropWords('reg', 0x80000000, 0x10000000)); root.append(mem)
uart = fdt.Node('serial@9000000'); uart.append(fdt.PropStrings('compatible', 'arm,pl011')); uart.append(fdt.PropWords('reg', 0x9000000, 0x1000)); uart.append(fdt.PropStrings('status', 'okay')); root.append(uart)
open('board.dtb', 'wb').write(t.to_dtb(version=17))
print('ok')
