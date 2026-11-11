export fn revlens_scale(out: [*]addrspace(.global) f32, x: [*]addrspace(.global) const f32, k: f32) callconv(.amdgcn_kernel) void {
    out[0] = x[0] * k;
}
export fn revlens_add(out: [*]addrspace(.global) f32, a: f32, b: f32) callconv(.amdgcn_kernel) void {
    out[0] = a + b;
}
