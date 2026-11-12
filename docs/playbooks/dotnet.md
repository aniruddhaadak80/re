# .NET playbook

.NET assemblies are PE files with a CLR header and metadata tables. Single file bundles and
ReadyToRun images hide the assemblies inside a native host.

## Recognise
- `analyze_file` reports `dotnet` and the target framework when the metadata names it.
- `managed_dotnet_info` shows the runtime version, flags (IL only, 32-bit preferred), strong name and the assembly references.

## First pass
1. `managed_dotnet_info` for the module, references and resources.
2. `managed_dotnet_types` with a namespace filter to see the shape of the program.
3. `managed_dotnet_search` for strings in the user string heap, type names or member names.
4. `managed_pinvoke_map` lists P/Invoke imports, which link managed code to native DLLs.

## Code
1. `managed_dotnet_method_il` shows the IL of one method with tokens resolved to names.
2. Look at static constructors (`.cctor`) and `Main` first. Obfuscators often move setup into module initializers.
3. `managed_compare_members` diffs two builds at the member level.

## Bridges that help
- ILSpy (`bridge_ilspy_decompile`) for C# source of a type or the whole assembly.

## Verify
- Cite the metadata token (for example 0x06000012) and the IL offset for each claim.
