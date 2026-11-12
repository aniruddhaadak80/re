// Objective-C and Swift dispatch metadata for Mach-O images (inspect_native_dispatch_metadata).

import { MachImage } from './macho-image.js';
import { readObjc, type ObjcMetadata } from './objc.js';
import { readSwift, type SwiftMetadata } from './swift.js';
import { machoSlices } from '../bin/container.js';
import { page, ParseError } from '../util.js';

export { MachImage, POINTER_FORMATS, type Fixup, type MSection, type MSegment } from './macho-image.js';
export { readObjc, objcDisplayName, type ObjcMetadata, type ObjcClass, type ObjcCategory, type ObjcProtocol, type ObjcMethod, type ObjcIvar, type ObjcProperty } from './objc.js';
export { readSwift, SwiftReader, type SwiftMetadata, type SwiftType, type SwiftField, type SwiftProtocol, type SwiftConformance, type SwiftVtableEntry } from './swift.js';

export interface DispatchMetadata {
  arch: string; slices: string[]; fileType: number; imageBase: string;
  fixups: { source: string; pointerFormat?: string; count: number };
  objc: ObjcMetadata; swift: SwiftMetadata; notes: string[]; elapsedMs: number;
}

/** Read ObjC and Swift metadata of one Mach-O slice (fat files: arch picks the slice, default the first). */
export function nativeDispatchMetadata(bytes: Uint8Array, opts: { arch?: string; budgetMs?: number } = {}): DispatchMetadata {
  const t0 = Date.now();
  const deadline = t0 + Math.max(100, Math.min(opts.budgetMs ?? 30000, 600000));
  const img = new MachImage(bytes, opts.arch);
  const objc = readObjc(img, { deadline });
  const swift = readSwift(img, { deadline });
  return {
    arch: img.arch, slices: machoSlices(bytes).map((s) => s.arch), fileType: img.fileType, imageBase: '0x' + img.imageBase.toString(16),
    fixups: { source: img.fixupSource, ...(img.pointerFormat ? { pointerFormat: img.pointerFormat } : {}), count: img.fixups.size },
    objc, swift, notes: img.notes, elapsedMs: Date.now() - t0,
  };
}

export type DispatchView = 'summary' | 'objc-classes' | 'objc-categories' | 'objc-protocols' | 'objc-classrefs' | 'swift-types' | 'swift-protocols' | 'swift-conformances';
const VIEWS: DispatchView[] = ['summary', 'objc-classes', 'objc-categories', 'objc-protocols', 'objc-classrefs', 'swift-types', 'swift-protocols', 'swift-conformances'];

/** Agent view: a summary, or one paged list filtered by a case insensitive substring of the name. */
export function dispatchMetadataView(md: DispatchMetadata, view: string = 'summary', filter?: string, offset = 0, limit = 100): unknown {
  if (!VIEWS.includes(view as DispatchView)) throw new ParseError(`view must be one of ${VIEWS.join(', ')}`);
  const f = (filter ?? '').toLowerCase();
  const keep = (...names: (string | undefined)[]) => !f || names.some((n) => n?.toLowerCase().includes(f));
  const head = { arch: md.arch, slices: md.slices, fixups: md.fixups, elapsedMs: md.elapsedMs, truncated: md.objc.truncated || md.swift.truncated };
  if (view === 'summary') {
    const o = md.objc, s = md.swift;
    const kinds: Record<string, number> = {};
    for (const t of s.types) kinds[t.kind] = (kinds[t.kind] ?? 0) + 1;
    return {
      ...head, imageBase: md.imageBase, notes: md.notes,
      objc: {
        present: o.present, imageInfo: o.imageInfo, classes: o.classes.length, swiftClasses: o.classes.filter((c) => c.swift).length,
        categories: o.categories.length, protocols: o.protocols.length, selectorRefs: o.selectorRefs, classRefs: o.classRefs.length, methodNames: o.methodNames,
        instanceMethods: o.classes.reduce((n, c) => n + c.methods.length, 0), classMethods: o.classes.reduce((n, c) => n + c.classMethods.length, 0),
        ivars: o.classes.reduce((n, c) => n + c.ivars.length, 0), properties: o.classes.reduce((n, c) => n + c.properties.length, 0),
        relativeMethodLists: o.classes.filter((c) => c.methodListKind === 'relative').length,
        sampleClasses: o.classes.slice(0, 20).map((c) => c.demangledName ?? c.name), errors: o.errors.slice(0, 20),
      },
      swift: {
        present: s.present, sections: s.sections, types: s.types.length, typeKinds: kinds, protocols: s.protocols.length, conformances: s.conformances.length,
        fields: s.types.reduce((n, t) => n + t.fields.length, 0), unresolvedFieldTypes: s.types.reduce((n, t) => n + t.fields.filter((x) => x.type === null && x.mangledType).length, 0),
        vtableEntries: s.types.reduce((n, t) => n + (t.vtable?.length ?? 0), 0), reflectionStrings: s.reflectionStrings,
        modules: [...new Set(s.types.map((t) => t.module).filter(Boolean))].slice(0, 50), errors: s.errors.slice(0, 20),
      },
    };
  }
  const lists: Record<Exclude<DispatchView, 'summary'>, () => unknown[]> = {
    'objc-classes': () => md.objc.classes.filter((c) => keep(c.name, c.demangledName, c.superclass?.name)),
    'objc-categories': () => md.objc.categories.filter((c) => keep(c.name, c.class.name)),
    'objc-protocols': () => md.objc.protocols.filter((p) => keep(p.name, p.demangledName)),
    'objc-classrefs': () => md.objc.classRefs.filter((c) => keep(c.name)),
    'swift-types': () => md.swift.types.filter((t) => keep(t.name, t.mangledName)),
    'swift-protocols': () => md.swift.protocols.filter((p) => keep(p.name)),
    'swift-conformances': () => md.swift.conformances.filter((c) => keep(c.protocol, c.type)),
  };
  return { ...head, view, filter: filter ?? null, ...page(lists[view as Exclude<DispatchView, 'summary'>](), offset, limit) };
}
