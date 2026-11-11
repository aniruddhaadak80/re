// Old Swift symbol demangler (Swift 1 to 3 mangling, prefix _T, and ObjC runtime names _TtC...). Ported from
// swift/lib/Demangling/OldDemangler.cpp (swift-6.0.3-RELEASE), Copyright (c) 2014-2024 Apple Inc. and the
// Swift project authors, Apache License v2.0 with Runtime Library Exception. See README for credit.

import {
  Node, NONE, K, type Kind, FunctionSigSpecializationParamKind, VALUE_WITNESSES, STDLIB_NAME, MANGLING_MODULE_OBJC,
  MANGLING_MODULE_CLANG_IMPORTER, charCode,
} from './nodes.js';
import * as N from './nodes.js';
import { decodePunycodeString } from './punycode.js';

interface Factory { createNode(k: Kind, payload?: string | number): Node }

function isStartOfIdentifier(c: string): boolean { return (c >= '0' && c <= '9') || c === 'o'; }
function isStartOfNominalType(c: string): boolean { return c === 'C' || c === 'V' || c === 'O'; }
function isStartOfEntity(c: string): boolean { return 'FIvPsZ'.includes(c) || isStartOfNominalType(c); }
function nominalTypeMarkerToNodeKind(c: string): Kind { return c === 'C' ? K.Class : c === 'V' ? K.Structure : c === 'O' ? K.Enum : K.Identifier; }

class NameSource {
  constructor(public Text: string) {}
  hasAtLeast(len: number): boolean { return len <= this.Text.length; }
  isEmpty(): boolean { return this.Text.length === 0; }
  peek(): string { return this.isEmpty() ? '.' : this.Text[0]!; }
  next(): string { const c = this.peek(); if (!this.isEmpty()) this.advanceOffset(1); return c; }
  nextIf(c: string): boolean {
    if (c.length !== 1) { if (!this.Text.startsWith(c)) return false; this.advanceOffset(c.length); return true; }
    if (this.isEmpty() || this.peek() !== c) return false;
    this.advanceOffset(1);
    return true;
  }
  slice(len: number): string { return this.Text.substr(0, len); }
  str(): string { return this.Text; }
  advanceOffset(len: number): void { this.Text = this.Text.substr(len); }
  getString(): string { const r = this.Text; this.advanceOffset(this.Text.length); return r; }
  /** Read up to (not including) c; returns undefined when c is not found. */
  readUntil(c: string): string | undefined {
    const i = this.Text.indexOf(c);
    if (i < 0) { this.Text = ''; return undefined; }
    const r = this.Text.slice(0, i); this.advanceOffset(i); return r;
  }
}

class OldDemangler {
  Substitutions: Node[] = [];
  Mangled: NameSource;
  static readonly MaxDepth = 1024;
  constructor(mangled: string, public Factory: Factory) { this.Mangled = new NameSource(mangled); }

  demangleTopLevel(): Node {
  if (!this.Mangled.nextIf("_T"))
    return NONE;

  let topLevel = this.Factory.createNode(K.Global);

  // First demangle any specialization prefixes.
  if (this.Mangled.nextIf("TS")) {
    do {
      { let _node = this.demangleSpecializedAttribute(0); if (!_node) return NONE; this.addChild(topLevel, _node); }

      // The Substitution header does not share state with the rest
      // of the mangling.
      this.Substitutions = [];
    } while (this.Mangled.nextIf("_TTS"));

    // Then check that we have a global.
    if (!this.Mangled.nextIf("_T"))
      return NONE;

  } else if (this.Mangled.nextIf("To")) {
    this.addChild(topLevel, this.Factory.createNode(K.ObjCAttribute));
  } else if (this.Mangled.nextIf("TO")) {
    this.addChild(topLevel, this.Factory.createNode(K.NonObjCAttribute));
  } else if (this.Mangled.nextIf("TD")) {
    this.addChild(topLevel, this.Factory.createNode(K.DynamicAttribute));
  } else if (this.Mangled.nextIf("Td")) {
    this.addChild(topLevel, this.Factory.createNode(
                        K.DirectMethodReferenceAttribute));
  } else if (this.Mangled.nextIf("TV")) {
    this.addChild(topLevel, this.Factory.createNode(K.VTableAttribute));
  }

  { let _node = this.demangleGlobal(0); if (!_node) return NONE; this.addChild(topLevel, _node); }

  // Add a suffix node if there's anything left unmangled.
  if (!this.Mangled.isEmpty()) {
    this.addChild(topLevel, this.Factory.createNode(K.Suffix,
                                      this.Mangled.getString()));
  }

  return topLevel;
}

  demangleTypeName(depth: number): Node { return this.demangleType(depth); }


  addChild(Parent: Node, Child: Node): void {
  Parent.addChild(Child);
}

  demangleDirectness(_depth: number): number | undefined {
  if (this.Mangled.nextIf('d'))
    return N.Directness.Direct;
  if (this.Mangled.nextIf('i'))
    return N.Directness.Indirect;
  return undefined;
}

  /** Natural number, or -1 when there is none (replaces the C++ out-parameter form). */
  demangleNaturalV(_depth: number): number {
  if (this.Mangled.isEmpty())
    return -1;
  let c = this.Mangled.next();
  if (c < '0' || c > '9')
    return -1;
  let num = charCode(c) - 48;
  let big: bigint | undefined;
  while (true) {
    if (this.Mangled.isEmpty() || this.Mangled.peek() < '0' || this.Mangled.peek() > '9')
      return big !== undefined ? Number(big) : num;
    c = this.Mangled.peek();
    this.Mangled.next();
    if (big !== undefined) { big = (big * 10n + BigInt(charCode(c) - 48)) & 0xffffffffffffffffn; continue; }
    num = (10 * num) + (charCode(c) - 48);
    // The C++ reads into a 64-bit unsigned index and wraps; keep that, switching to BigInt past 2^49.
    if (num > 2 ** 49) big = BigInt(num);
  }
}

  demangleBuiltinSizeV(depth: number): number {
  const num = this.demangleNaturalV(depth + 1);
  if (num < 0)
    return -1;
  if (this.Mangled.nextIf('_'))
    return num;
  return -1;
}

  demangleValueWitnessKind(_depth: number): number | undefined {
  if (this.Mangled.isEmpty())
    return undefined;
  let Code = this.Mangled.next();
  if (this.Mangled.isEmpty())
    return undefined;
  Code += this.Mangled.next();
  const i = VALUE_WITNESSES.findIndex((v) => v[0] === Code);
  return i < 0 ? undefined : i;
}

  demangleGlobal(depth: number): Node {
  if (depth > OldDemangler.MaxDepth || this.Mangled.isEmpty())
    return NONE;

  // Type metadata.
  if (this.Mangled.nextIf('M')) {
    if (this.Mangled.nextIf('P')) {
      let pattern =
          this.Factory.createNode(K.GenericTypeMetadataPattern);
      { let _node = this.demangleType(depth + 1); if (!_node) return NONE; this.addChild(pattern, _node); }
      return pattern;
    }
    if (this.Mangled.nextIf('a')) {
      let accessor =
        this.Factory.createNode(K.TypeMetadataAccessFunction);
      { let _node = this.demangleType(depth + 1); if (!_node) return NONE; this.addChild(accessor, _node); }
      return accessor;
    }
    if (this.Mangled.nextIf('L')) {
      let cache = this.Factory.createNode(K.TypeMetadataLazyCache);
      { let _node = this.demangleType(depth + 1); if (!_node) return NONE; this.addChild(cache, _node); }
      return cache;
    }
    if (this.Mangled.nextIf('m')) {
      let metaclass = this.Factory.createNode(K.Metaclass);
      { let _node = this.demangleType(depth + 1); if (!_node) return NONE; this.addChild(metaclass, _node); }
      return metaclass;
    }
    if (this.Mangled.nextIf('n')) {
      let nominalType =
          this.Factory.createNode(K.NominalTypeDescriptor);
      { let _node = this.demangleType(depth + 1); if (!_node) return NONE; this.addChild(nominalType, _node); }
      return nominalType;
    }
    if (this.Mangled.nextIf('f')) {
      let metadata = this.Factory.createNode(K.FullTypeMetadata);
      { let _node = this.demangleType(depth + 1); if (!_node) return NONE; this.addChild(metadata, _node); }
      return metadata;
    }
    if (this.Mangled.nextIf('p')) {
      let metadata = this.Factory.createNode(K.ProtocolDescriptor);
      { let _node = this.demangleProtocolName(depth + 1); if (!_node) return NONE; this.addChild(metadata, _node); }
      return metadata;
    }
    let metadata = this.Factory.createNode(K.TypeMetadata);
    { let _node = this.demangleType(depth + 1); if (!_node) return NONE; this.addChild(metadata, _node); }
    return metadata;
  }

  // Partial application thunks.
  if (this.Mangled.nextIf("PA")) {
    let kind: Kind = K.PartialApplyForwarder;
    if (this.Mangled.nextIf('o'))
      kind = K.PartialApplyObjCForwarder;
    let forwarder = this.Factory.createNode(kind);
    if (this.Mangled.nextIf("__T"))
      { let _node = this.demangleGlobal(depth + 1); if (!_node) return NONE; this.addChild(forwarder, _node); }
    return forwarder;
  }

  // Top-level types, for various consumers.
  if (this.Mangled.nextIf('t')) {
    let type = this.Factory.createNode(K.TypeMangling);
    { let _node = this.demangleType(depth + 1); if (!_node) return NONE; this.addChild(type, _node); }
    return type;
  }

  // Value witnesses.
  if (this.Mangled.nextIf('w')) {
    const w = this.demangleValueWitnessKind(depth + 1);
    if (w === undefined)
      return NONE;
    let witness =
      this.Factory.createNode(K.ValueWitness);
    let Idx = this.Factory.createNode(K.Index, w);
    witness.addChild(Idx);
    { let _node = this.demangleType(depth + 1); if (!_node) return NONE; this.addChild(witness, _node); }
    return witness;
  }

  // Offsets, value witness tables, and protocol witnesses.
  if (this.Mangled.nextIf('W')) {
    if (this.Mangled.nextIf('V')) {
      let witnessTable = this.Factory.createNode(K.ValueWitnessTable);
      { let _node = this.demangleType(depth + 1); if (!_node) return NONE; this.addChild(witnessTable, _node); }
      return witnessTable;
    }
    if (this.Mangled.nextIf('v')) {
      let fieldOffset = this.Factory.createNode(K.FieldOffset);
      { let _kind = this.demangleDirectness(depth + 1); if (_kind === undefined) return NONE; this.addChild(fieldOffset, this.Factory.createNode(K.Directness, _kind)); }
      { let _node = this.demangleEntity(depth + 1); if (!_node) return NONE; this.addChild(fieldOffset, _node); }
      return fieldOffset;
    }
    if (this.Mangled.nextIf('P')) {
      let witnessTable =
          this.Factory.createNode(K.ProtocolWitnessTable);
      { let _node = this.demangleProtocolConformance(depth + 1); if (!_node) return NONE; this.addChild(witnessTable, _node); }
      return witnessTable;
    }
    if (this.Mangled.nextIf('G')) {
      let witnessTable =
          this.Factory.createNode(K.GenericProtocolWitnessTable);
      { let _node = this.demangleProtocolConformance(depth + 1); if (!_node) return NONE; this.addChild(witnessTable, _node); }
      return witnessTable;
    }
    if (this.Mangled.nextIf('I')) {
      let witnessTable = this.Factory.createNode(
          K.GenericProtocolWitnessTableInstantiationFunction);
      { let _node = this.demangleProtocolConformance(depth + 1); if (!_node) return NONE; this.addChild(witnessTable, _node); }
      return witnessTable;
    }
    if (this.Mangled.nextIf('l')) {
      let accessor =
        this.Factory.createNode(K.LazyProtocolWitnessTableAccessor);
      { let _node = this.demangleType(depth + 1); if (!_node) return NONE; this.addChild(accessor, _node); }
      { let _node = this.demangleProtocolConformance(depth + 1); if (!_node) return NONE; this.addChild(accessor, _node); }
      return accessor;
    }
    if (this.Mangled.nextIf('L')) {
      let accessor =
        this.Factory.createNode(K.LazyProtocolWitnessTableCacheVariable);
      { let _node = this.demangleType(depth + 1); if (!_node) return NONE; this.addChild(accessor, _node); }
      { let _node = this.demangleProtocolConformance(depth + 1); if (!_node) return NONE; this.addChild(accessor, _node); }
      return accessor;
    }
    if (this.Mangled.nextIf('a')) {
      let tableTemplate =
        this.Factory.createNode(K.ProtocolWitnessTableAccessor);
      { let _node = this.demangleProtocolConformance(depth + 1); if (!_node) return NONE; this.addChild(tableTemplate, _node); }
      return tableTemplate;
    }
    if (this.Mangled.nextIf('t')) {
      let accessor = this.Factory.createNode(
          K.AssociatedTypeMetadataAccessor);
      { let _node = this.demangleProtocolConformance(depth + 1); if (!_node) return NONE; this.addChild(accessor, _node); }
      { let _node = this.demangleDeclName(depth + 1); if (!_node) return NONE; this.addChild(accessor, _node); }
      return accessor;
    }
    if (this.Mangled.nextIf('T')) {
      let accessor = this.Factory.createNode(
          K.AssociatedTypeWitnessTableAccessor);
      { let _node = this.demangleProtocolConformance(depth + 1); if (!_node) return NONE; this.addChild(accessor, _node); }
      { let _node = this.demangleDeclName(depth + 1); if (!_node) return NONE; this.addChild(accessor, _node); }
      { let _node = this.demangleProtocolName(depth + 1); if (!_node) return NONE; this.addChild(accessor, _node); }
      return accessor;
    }
    return NONE;
  }

  // Other thunks.
  if (this.Mangled.nextIf('T')) {
    if (this.Mangled.nextIf('R')) {
      let thunk = this.Factory.createNode(K.ReabstractionThunkHelper);
      if (!this.demangleReabstractSignature(thunk, depth + 1))
        return NONE;
      return thunk;
    }
    if (this.Mangled.nextIf('r')) {
      let thunk = this.Factory.createNode(K.ReabstractionThunk);
      if (!this.demangleReabstractSignature(thunk, depth + 1))
        return NONE;
      return thunk;
    }
    if (this.Mangled.nextIf('W')) {
      let thunk = this.Factory.createNode(K.ProtocolWitness);
      { let _node = this.demangleProtocolConformance(depth + 1); if (!_node) return NONE; this.addChild(thunk, _node); }
      // The entity is mangled in its own generic context.
      { let _node = this.demangleEntity(depth + 1); if (!_node) return NONE; this.addChild(thunk, _node); }
      return thunk;
    }
    return NONE;
  }

  // Everything else is just an entity.
  return this.demangleEntity(depth + 1);
}

  demangleGenericSpecialization(specialization: Node, depth: number): Node {
  if (depth > OldDemangler.MaxDepth)
    return NONE;

  while (!this.Mangled.nextIf('_')) {
    // Otherwise, we have another parameter. Demangle the type.
    let param = this.Factory.createNode(K.GenericSpecializationParam);
    { let _node = this.demangleType(depth + 1); if (!_node) return NONE; this.addChild(param, _node); }

    // Then parse any conformances until we find an underscore. Pop off the
    // underscore since it serves as the end of our mangling list.
    while (!this.Mangled.nextIf('_')) {
      { let _node = this.demangleProtocolConformance(depth + 1); if (!_node) return NONE; this.addChild(param, _node); }
    }

    // Add the parameter to our specialization list.
    specialization.addChild(param);
  }

  return specialization;
}


  demangleFuncSigSpecializationConstantProp(parent: Node, depth: number): boolean {
  // Then figure out what was actually constant propagated. First check if
  // we have a function.
  if (this.Mangled.nextIf("fr")) {
    // Demangle the identifier
    let name = this.demangleIdentifier(depth + 1);
    if (!name || !this.Mangled.nextIf('_'))
      return false;
    parent.addChild(this.Factory.createNode(K.FunctionSignatureSpecializationParamKind, FunctionSigSpecializationParamKind.ConstantPropFunction));
    parent.addChild(this.Factory.createNode(K.FunctionSignatureSpecializationParamPayload, name.getText()));
    return true;
  }

  if (this.Mangled.nextIf('g')) {
    let name = this.demangleIdentifier(depth + 1);
    if (!name || !this.Mangled.nextIf('_'))
      return false;
    parent.addChild(this.Factory.createNode(K.FunctionSignatureSpecializationParamKind, FunctionSigSpecializationParamKind.ConstantPropGlobal));
    parent.addChild(this.Factory.createNode(K.FunctionSignatureSpecializationParamPayload, name.getText()));
    return true;
  }

  if (this.Mangled.nextIf('i')) {
    const Str = this.Mangled.readUntil('_');
    if (Str === undefined || !this.Mangled.nextIf('_'))
      return false;
    parent.addChild(this.Factory.createNode(K.FunctionSignatureSpecializationParamKind, FunctionSigSpecializationParamKind.ConstantPropInteger));
    parent.addChild(this.Factory.createNode(K.FunctionSignatureSpecializationParamPayload, Str));
    return true;
  }

  if (this.Mangled.nextIf("fl")) {
    const Str = this.Mangled.readUntil('_');
    if (Str === undefined || !this.Mangled.nextIf('_'))
      return false;
    parent.addChild(this.Factory.createNode(K.FunctionSignatureSpecializationParamKind, FunctionSigSpecializationParamKind.ConstantPropFloat));
    parent.addChild(this.Factory.createNode(K.FunctionSignatureSpecializationParamPayload, Str));
    return true;
  }

  if (this.Mangled.nextIf("s")) {
    // Skip: 'e' encoding 'v' str. encoding is a 0 or 1 and str is a string of
    // length less than or equal to 32. We do not specialize strings with a
    // length greater than 32.
    if (!this.Mangled.nextIf('e'))
      return false;
    let encoding = this.Mangled.peek();
    if (encoding != '0' && encoding != '1')
      return false;
    let encodingStr = '';
    if (encoding == '0')
      encodingStr += "u8";
    else
      encodingStr += "u16";
    this.Mangled.advanceOffset(1);

    if (!this.Mangled.nextIf('v'))
      return false;
    let str = this.demangleIdentifier(depth + 1);
    if (!str || !this.Mangled.nextIf('_'))
      return false;

    parent.addChild(this.Factory.createNode(K.FunctionSignatureSpecializationParamKind, FunctionSigSpecializationParamKind.ConstantPropString));
    parent.addChild(this.Factory.createNode(K.FunctionSignatureSpecializationParamPayload, encodingStr));
    parent.addChild(this.Factory.createNode(K.FunctionSignatureSpecializationParamPayload, str.getText()));
    return true;
  }

  // Unknown constant prop specialization
  return false;
}

  demangleFuncSigSpecializationClosureProp(parent: Node, depth: number): boolean {
  // We don't actually demangle the function or types for now. But we do want
  // to signal that we specialized a closure.

  let name = this.demangleIdentifier(depth + 1);
  if (!name) {
    return false;
  }

  parent.addChild(this.Factory.createNode(K.FunctionSignatureSpecializationParamKind, FunctionSigSpecializationParamKind.ClosureProp));
  parent.addChild(this.Factory.createNode(K.FunctionSignatureSpecializationParamPayload, name.getText()));

  // Then demangle types until we fail.
  let type = NONE;
  while (this.Mangled.peek() != '_' && (type = this.demangleType(depth + 1))) {
    parent.addChild(type);
  }

  // Eat last '_'
  if (!this.Mangled.nextIf('_'))
    return false;

  return true;
}

  demangleFunctionSignatureSpecialization(specialization: Node, depth: number): Node {
  // Until we hit the last '_' in our specialization info...
  while (!this.Mangled.nextIf('_')) {
    // Create the parameter.
    let param =
      this.Factory.createNode(K.FunctionSignatureSpecializationParam);

    // First handle options.
    if (this.Mangled.nextIf("n_")) {
      // Leave the parameter empty.
    } else if (this.Mangled.nextIf("cp")) {
      if (!this.demangleFuncSigSpecializationConstantProp(param, depth + 1))
        return NONE;
    } else if (this.Mangled.nextIf("cl")) {
      if (!this.demangleFuncSigSpecializationClosureProp(param, depth + 1))
        return NONE;
    } else if (this.Mangled.nextIf("i_")) {
      let result = this.Factory.createNode(K.FunctionSignatureSpecializationParamKind, FunctionSigSpecializationParamKind.BoxToValue);
      if (!result)
        return NONE;
      param.addChild(result);
    } else if (this.Mangled.nextIf("k_")) {
      let result = this.Factory.createNode(K.FunctionSignatureSpecializationParamKind, FunctionSigSpecializationParamKind.BoxToStack);
      if (!result)
        return NONE;
      param.addChild(result);
    } else if (this.Mangled.nextIf("r_")) {
      let result = this.Factory.createNode(K.FunctionSignatureSpecializationParamKind, FunctionSigSpecializationParamKind.InOutToOut);
      if (!result)
        return NONE;
      param.addChild(result);
    } else {
      // Otherwise handle option sets.
      let Value = 0;
      if (this.Mangled.nextIf('d')) {
        Value |=
          FunctionSigSpecializationParamKind.Dead;
      }

      if (this.Mangled.nextIf('g')) {
        Value |=
            FunctionSigSpecializationParamKind.OwnedToGuaranteed;
      }

      if (this.Mangled.nextIf('o')) {
        Value |=
            FunctionSigSpecializationParamKind.GuaranteedToOwned;
      }

      if (this.Mangled.nextIf('s')) {
        Value |= FunctionSigSpecializationParamKind.SROA;
      }

      if (!this.Mangled.nextIf('_'))
        return NONE;

      if (!Value)
        return NONE;

      let result = this.Factory.createNode(
          K.FunctionSignatureSpecializationParamKind, Value);
      if (!result)
        return NONE;
      param.addChild(result);
    }

    specialization.addChild(param);
  }

  return specialization;
}

  demangleSpecializedAttribute(depth: number): Node {
  let isNotReAbstracted = false;
  if (this.Mangled.nextIf("g") || (isNotReAbstracted = this.Mangled.nextIf("r"))) {
    let spec = this.Factory.createNode(isNotReAbstracted ?
                            K.GenericSpecializationNotReAbstracted :
                            K.GenericSpecialization);

    // Create a node if the specialization is serialized.
    if (this.Mangled.nextIf("q")) {
      let kind = K.IsSerialized;
      spec.addChild(this.Factory.createNode(kind));
    }

    // Create a node for the pass id.
    spec.addChild(this.Factory.createNode(K.SpecializationPassID,
                                    charCode(this.Mangled.next()) - 48));

    // And then mangle the generic specialization.
    return this.demangleGenericSpecialization(spec, depth + 1);
  }
  if (this.Mangled.nextIf("f")) {
    let spec =
        this.Factory.createNode(K.FunctionSignatureSpecialization);

    // Create a node if the specialization is serialized.
    if (this.Mangled.nextIf("q")) {
      let kind = K.IsSerialized;
      spec.addChild(this.Factory.createNode(kind));
    }

    // Add the pass id.
    spec.addChild(this.Factory.createNode(K.SpecializationPassID,
                                    charCode(this.Mangled.next()) - 48));

    // Then perform the function signature specialization.
    return this.demangleFunctionSignatureSpecialization(spec, depth + 1);
  }

  // We don't know how to handle this specialization.
  return NONE;
}

  demangleDeclName(depth: number): Node {
  // decl-name ::= local-decl-name
  // local-decl-name ::= 'L' index identifier
  if (this.Mangled.nextIf('L')) {
    let discriminator = this.demangleIndexAsNode(depth + 1);
    if (!discriminator) return NONE;

    let name = this.demangleIdentifier(depth + 1);
    if (!name) return NONE;

    let localName = this.Factory.createNode(K.LocalDeclName);
    localName.addChild(discriminator);
    localName.addChild(name);
    return localName;

  } else if (this.Mangled.nextIf('P')) {
    let discriminator = this.demangleIdentifier(depth + 1);
    if (!discriminator) return NONE;

    let name = this.demangleIdentifier(depth + 1);
    if (!name) return NONE;

    let privateName = this.Factory.createNode(K.PrivateDeclName);
    privateName.addChild(discriminator);
    privateName.addChild(name);
    return privateName;
  }

  // decl-name ::= identifier
  return this.demangleIdentifier(depth + 1);
}

  demangleIdentifier(depth: number, kind?: Kind): Node {
  if (this.Mangled.isEmpty())
    return NONE;

  let isPunycoded = this.Mangled.nextIf('X');

  let isOperator = false;
  if (this.Mangled.nextIf('o')) {
    isOperator = true;
    // Operator identifiers aren't valid in the contexts that are
    // building more specific identifiers.
    if (kind !== undefined) return NONE;

    let op_mode = this.Mangled.next();
    switch (op_mode) {
    case 'p':
      kind = K.PrefixOperator;
      break;
    case 'P':
      kind = K.PostfixOperator;
      break;
    case 'i':
      kind = K.InfixOperator;
      break;
    default:
      return NONE;
    }
  }

  if (kind === undefined) kind = K.Identifier;

  let length = this.demangleNaturalV(depth + 1);
  if (length < 0)
    return NONE;
  if (!this.Mangled.hasAtLeast(length))
    return NONE;

  let identifier = this.Mangled.slice(length);
  this.Mangled.advanceOffset(length);

  // Decode Unicode identifiers.
  if (isPunycoded) identifier = decodePunycodeString(identifier) ?? '';
  if (identifier.length === 0)
    return NONE;

  // Decode operator names.
  if (isOperator) {
    const op_char_table = "& @/= >    <*!|+?%-~   ^ .";
    let opDecodeBuffer = '';
    for (const c of identifier) {
      if (charCode(c) >= 0x80) {
        // Pass through Unicode characters.
        opDecodeBuffer += c;
        continue;
      }
      if (c < 'a' || c > 'z')
        return NONE;
      let o = op_char_table[charCode(c) - 97]!;
      if (o == ' ')
        return NONE;
      opDecodeBuffer += o;
    }
    identifier = opDecodeBuffer;
  }

  return this.Factory.createNode(kind, identifier);
}
  demangleIndexV(depth: number): number {
  if (this.Mangled.nextIf('_'))
    return 0;
  const natural = this.demangleNaturalV(depth + 1);
  if (natural >= 0) {
    if (!this.Mangled.nextIf('_'))
      return -1;
    return natural + 1;
  }
  return -1;
}

  demangleIndexAsNode(depth: number, kind: Kind = K.Number): Node {
  let index = 0;
  if (!((index = this.demangleIndexV(depth)) >= 0))
    return NONE;
  return this.Factory.createNode(kind, index);
}

  createSwiftType(typeKind: Kind, name: string): Node {
  let type = this.Factory.createNode(typeKind);
  type.addChild(this.Factory.createNode(K.Module, STDLIB_NAME));
  type.addChild(this.Factory.createNode(K.Identifier, name));
  return type;
}


  demangleSubstitutionIndex(depth: number): Node {
  if (this.Mangled.isEmpty())
    return NONE;
  if (this.Mangled.nextIf('o'))
    return this.Factory.createNode(K.Module, MANGLING_MODULE_OBJC);
  if (this.Mangled.nextIf('C'))
    return this.Factory.createNode(K.Module,
                              MANGLING_MODULE_CLANG_IMPORTER);
  if (this.Mangled.nextIf('a'))
    return this.createSwiftType(K.Structure, "Array");
  if (this.Mangled.nextIf('b'))
    return this.createSwiftType(K.Structure, "Bool");
  if (this.Mangled.nextIf('c'))
    return this.createSwiftType(K.Structure, "UnicodeScalar");
  if (this.Mangled.nextIf('d'))
    return this.createSwiftType(K.Structure, "Double");
  if (this.Mangled.nextIf('f'))
    return this.createSwiftType(K.Structure, "Float");
  if (this.Mangled.nextIf('i'))
    return this.createSwiftType(K.Structure, "Int");
  if (this.Mangled.nextIf('V'))
    return this.createSwiftType(K.Structure, "UnsafeRawPointer");
  if (this.Mangled.nextIf('v'))
    return this.createSwiftType(K.Structure, "UnsafeMutableRawPointer");
  if (this.Mangled.nextIf('P'))
    return this.createSwiftType(K.Structure, "UnsafePointer");
  if (this.Mangled.nextIf('p'))
    return this.createSwiftType(K.Structure, "UnsafeMutablePointer");
  if (this.Mangled.nextIf('q'))
    return this.createSwiftType(K.Enum, "Optional");
  if (this.Mangled.nextIf('Q'))
    return this.createSwiftType(K.Enum, "ImplicitlyUnwrappedOptional");
  if (this.Mangled.nextIf('R'))
    return this.createSwiftType(K.Structure, "UnsafeBufferPointer");
  if (this.Mangled.nextIf('r'))
    return this.createSwiftType(K.Structure, "UnsafeMutableBufferPointer");
  if (this.Mangled.nextIf('S'))
    return this.createSwiftType(K.Structure, "String");
  if (this.Mangled.nextIf('u'))
    return this.createSwiftType(K.Structure, "UInt");
  let index_sub = 0;
  if (!((index_sub = this.demangleIndexV(depth)) >= 0))
    return NONE;
  if (index_sub >= this.Substitutions.length)
    return NONE;
  return this.Substitutions[index_sub]!;
}

  demangleModule(depth: number): Node {
  if (this.Mangled.nextIf('s')) {
    return this.Factory.createNode(K.Module, STDLIB_NAME);
  }
  if (this.Mangled.nextIf('S')) {
    let module = this.demangleSubstitutionIndex(depth + 1);
    if (!module)
      return NONE;
    if (module.getKind() != K.Module)
      return NONE;
    return module;
  }

  let module = this.demangleIdentifier(depth + 1, K.Module);
  if (!module) return NONE;
  this.Substitutions.push(module);
  return module;
}

  demangleDeclarationName(kind: Kind, depth: number): Node {
  let context = this.demangleContext(depth + 1);
  if (!context) return NONE;

  let name = this.demangleDeclName(depth + 1);
  if (!name) return NONE;

  let decl = this.Factory.createNode(kind);
  decl.addChild(context);
  decl.addChild(name);
  this.Substitutions.push(decl);
  return decl;
}

  demangleProtocolName(depth: number): Node {
  let proto = this.demangleProtocolNameImpl(depth);
  if (!proto) return NONE;

  let type = this.Factory.createNode(K.Type);
  type.addChild(proto);
  return type;
}

  demangleProtocolNameGivenContext(context: Node, depth: number): Node {
  let name = this.demangleDeclName(depth + 1);
  if (!name) return NONE;

  let proto = this.Factory.createNode(K.Protocol);
  proto.addChild(context);
  proto.addChild(name);
  this.Substitutions.push(proto);
  return proto;
}

  demangleProtocolNameImpl(depth: number): Node {
  if (depth > OldDemangler.MaxDepth)
    return NONE;

  // There's an ambiguity in <protocol> between a substitution of
  // the protocol and a substitution of the protocol's context, so
  // we have to duplicate some of the logic from
  // this.demangleDeclarationName.
  if (this.Mangled.nextIf('S')) {
    let sub = this.demangleSubstitutionIndex(depth + 1);
    if (!sub) return NONE;
    if (sub.getKind() == K.Protocol)
      return sub;

    if (sub.getKind() != K.Module)
      return NONE;

    return this.demangleProtocolNameGivenContext(sub, depth + 1);
  }

  if (this.Mangled.nextIf('s')) {
    let stdlib = this.Factory.createNode(K.Module, STDLIB_NAME);

    return this.demangleProtocolNameGivenContext(stdlib, depth + 1);
  }

  return this.demangleDeclarationName(K.Protocol, depth + 1);
}

  demangleNominalType(depth: number): Node {
  if (this.Mangled.nextIf('S'))
    return this.demangleSubstitutionIndex(depth + 1);
  if (this.Mangled.nextIf('V'))
    return this.demangleDeclarationName(K.Structure, depth + 1);
  if (this.Mangled.nextIf('O'))
    return this.demangleDeclarationName(K.Enum, depth + 1);
  if (this.Mangled.nextIf('C'))
    return this.demangleDeclarationName(K.Class, depth + 1);
  if (this.Mangled.nextIf('P'))
    return this.demangleDeclarationName(K.Protocol, depth + 1);
  return NONE;
}

  demangleBoundGenericArgs(nominalType: Node, depth: number): Node {
  if (nominalType.getNumChildren() == 0)
    return NONE;

  // Generic arguments for the outermost type come first.
  let parentOrModule = nominalType.getChild(0);

  if (parentOrModule.getKind() != K.Module &&
      parentOrModule.getKind() != K.Function &&
      parentOrModule.getKind() != K.Extension) {
    parentOrModule = this.demangleBoundGenericArgs(parentOrModule, depth + 1);
    if (!parentOrModule)
      return NONE;

    // Rebuild this type with the new parent type, which may have
    // had its generic arguments applied.
    let result = this.Factory.createNode(nominalType.getKind());
    result.addChild(parentOrModule);
    for (let ndx = 1; ndx < nominalType.getNumChildren(); ++ndx)
      result.addChild(nominalType.getChild(ndx));

    nominalType = result;
  }

  let args = this.Factory.createNode(K.TypeList);
  while (!this.Mangled.nextIf('_')) {
    let type = this.demangleType(depth + 1);
    if (!type)
      return NONE;
    args.addChild(type);
    if (this.Mangled.isEmpty())
      return NONE;
  }

  // If there were no arguments at this level there is nothing left
  // to do.
  if (args.getNumChildren() == 0)
    return nominalType;

  // Otherwise, build a bound generic type node from the unbound
  // type and arguments.
  let unboundType = this.Factory.createNode(K.Type);
  unboundType.addChild(nominalType);

  let kind;
  switch (nominalType.getKind()) { // look through Type node
    case K.Class:
      kind = K.BoundGenericClass;
      break;
    case K.Structure:
      kind = K.BoundGenericStructure;
      break;
    case K.Enum:
      kind = K.BoundGenericEnum;
      break;
    default:
      return NONE;
  }
  let result = this.Factory.createNode(kind);
  result.addChild(unboundType);
  result.addChild(args);
  return result;
}

  demangleBoundGenericType(depth: number): Node {
  // bound-generic-type ::= 'G' nominal-type (args+ '_')+
  //
  // Each level of nominal type nesting has its own list of arguments.

  let nominalType = this.demangleNominalType(depth + 1);
  if (!nominalType)
    return NONE;

  return this.demangleBoundGenericArgs(nominalType, depth + 1);
}

  demangleContext(depth: number): Node {
  // context ::= module
  // context ::= entity
  // context ::= 'E' module context (extension defined in a different module)
  // context ::= 'e' module context generic-signature (constrained extension)
  if (this.Mangled.isEmpty()) return NONE;
  if (this.Mangled.nextIf('E')) {
    let ext = this.Factory.createNode(K.Extension);
    let def_module = this.demangleModule(depth + 1);
    if (!def_module) return NONE;
    let type = this.demangleContext(depth + 1);
    if (!type) return NONE;
    ext.addChild(def_module);
    ext.addChild(type);
    return ext;
  }
  if (this.Mangled.nextIf('e')) {
    let ext = this.Factory.createNode(K.Extension);
    let def_module = this.demangleModule(depth + 1);
    if (!def_module) return NONE;
    let sig = this.demangleGenericSignature(depth + 1);
    // The generic context is currently re-specified by the type mangling.
    // If we ever remove 'self' from manglings, we should stop resetting the
    // context here.
    if (!sig) return NONE;
    let type = this.demangleContext(depth + 1);
    if (!type) return NONE;

    ext.addChild(def_module);
    ext.addChild(type);
    ext.addChild(sig);
    return ext;
  }
  if (this.Mangled.nextIf('S'))
    return this.demangleSubstitutionIndex(depth + 1);
  if (this.Mangled.nextIf('s'))
    return this.Factory.createNode(K.Module, STDLIB_NAME);
  if (this.Mangled.nextIf('G'))
    return this.demangleBoundGenericType(depth + 1);
  if (isStartOfEntity(this.Mangled.peek()))
    return this.demangleEntity(depth + 1);
  return this.demangleModule(depth + 1);
}

  demangleProtocolList(depth: number): Node {
  let proto_list = this.Factory.createNode(K.ProtocolList);
  let type_list = this.Factory.createNode(K.TypeList);
  proto_list.addChild(type_list);
  while (!this.Mangled.nextIf('_')) {
    let proto = this.demangleProtocolName(depth + 1);
    if (!proto)
      return NONE;
    type_list.addChild(proto);
  }
  return proto_list;
}

  demangleProtocolConformance(depth: number): Node {
  let type = this.demangleType(depth + 1);
  if (!type)
    return NONE;
  let protocol = this.demangleProtocolName(depth + 1);
  if (!protocol)
    return NONE;
  let context = this.demangleContext(depth + 1);
  if (!context)
    return NONE;
  let proto_conformance =
      this.Factory.createNode(K.ProtocolConformance);
  proto_conformance.addChild(type);
  proto_conformance.addChild(protocol);
  proto_conformance.addChild(context);
  return proto_conformance;
}


  demangleEntity(depth: number): Node {
  if (depth > OldDemangler.MaxDepth)
    return NONE;

  // static?
  let isStatic = this.Mangled.nextIf('Z');

  // entity-kind
  let entityBasicKind;
  if (this.Mangled.nextIf('F')) {
    entityBasicKind = K.Function;
  } else if (this.Mangled.nextIf('v')) {
    entityBasicKind = K.Variable;
  } else if (this.Mangled.nextIf('I')) {
    entityBasicKind = K.Initializer;
  } else if (this.Mangled.nextIf('i')) {
    entityBasicKind = K.Subscript;
  } else {
    return this.demangleNominalType(depth + 1);
  }

  let context = this.demangleContext(depth + 1);
  if (!context) return NONE;

  // entity-name
  let entityKind;
  let hasType = true;
  // Wrap the enclosed entity in a variable or subscript node
  let wrapEntity = false;
  let name = NONE;
  if (this.Mangled.nextIf('D')) {
    entityKind = K.Deallocator;
    hasType = false;
  } else if (this.Mangled.nextIf('d')) {
    entityKind = K.Destructor;
    hasType = false;
  } else if (this.Mangled.nextIf('e')) {
    entityKind = K.IVarInitializer;
    hasType = false;
  } else if (this.Mangled.nextIf('E')) {
    entityKind = K.IVarDestroyer;
    hasType = false;
  } else if (this.Mangled.nextIf('C')) {
    entityKind = K.Allocator;
  } else if (this.Mangled.nextIf('c')) {
    entityKind = K.Constructor;
  } else if (this.Mangled.nextIf('a')) {
    wrapEntity = true;
    if (this.Mangled.nextIf('O')) {
      entityKind = K.OwningMutableAddressor;
    } else if (this.Mangled.nextIf('o')) {
      entityKind = K.NativeOwningMutableAddressor;
    } else if (this.Mangled.nextIf('p')) {
      entityKind = K.NativePinningMutableAddressor;
    } else if (this.Mangled.nextIf('u')) {
      entityKind = K.UnsafeMutableAddressor;
    } else {
      return NONE;
    }
    name = this.demangleDeclName(depth + 1);
    if (!name) return NONE;
  } else if (this.Mangled.nextIf('l')) {
    wrapEntity = true;
    if (this.Mangled.nextIf('O')) {
      entityKind = K.OwningAddressor;
    } else if (this.Mangled.nextIf('o')) {
      entityKind = K.NativeOwningAddressor;
    } else if (this.Mangled.nextIf('p')) {
      entityKind = K.NativePinningAddressor;
    } else if (this.Mangled.nextIf('u')) {
      entityKind = K.UnsafeAddressor;
    } else {
      return NONE;
    }
    name = this.demangleDeclName(depth + 1);
    if (!name) return NONE;
  } else if (this.Mangled.nextIf('g')) {
    wrapEntity = true;
    entityKind = K.Getter;
    name = this.demangleDeclName(depth + 1);
    if (!name) return NONE;
  } else if (this.Mangled.nextIf('G')) {
    wrapEntity = true;
    entityKind = K.GlobalGetter;
    name = this.demangleDeclName(depth + 1);
    if (!name) return NONE;
  } else if (this.Mangled.nextIf('s')) {
    wrapEntity = true;
    entityKind = K.Setter;
    name = this.demangleDeclName(depth + 1);
    if (!name) return NONE;
  } else if (this.Mangled.nextIf('m')) {
    wrapEntity = true;
    entityKind = K.MaterializeForSet;
    name = this.demangleDeclName(depth + 1);
    if (!name) return NONE;
  } else if (this.Mangled.nextIf('w')) {
    wrapEntity = true;
    entityKind = K.WillSet;
    name = this.demangleDeclName(depth + 1);
    if (!name) return NONE;
  } else if (this.Mangled.nextIf('W')) {
    wrapEntity = true;
    entityKind = K.DidSet;
    name = this.demangleDeclName(depth + 1);
    if (!name) return NONE;
  } else if (this.Mangled.nextIf('r')) {
    wrapEntity = true;
    entityKind = K.ReadAccessor;
    name = this.demangleDeclName(depth + 1);
    if (!name) return NONE;
  } else if (this.Mangled.nextIf('M')) {
    wrapEntity = true;
    entityKind = K.ModifyAccessor;
    name = this.demangleDeclName(depth + 1);
    if (!name) return NONE;
  } else if (this.Mangled.nextIf('U')) {
    entityKind = K.ExplicitClosure;
    name = this.demangleIndexAsNode(depth + 1);
    if (!name) return NONE;
  } else if (this.Mangled.nextIf('u')) {
    entityKind = K.ImplicitClosure;
    name = this.demangleIndexAsNode(depth + 1);
    if (!name) return NONE;
  } else if (entityBasicKind == K.Initializer) {
    // entity-name ::= 'A' index
    if (this.Mangled.nextIf('A')) {
      entityKind = K.DefaultArgumentInitializer;
      name = this.demangleIndexAsNode(depth + 1);
      if (!name) return NONE;
    // entity-name ::= 'i'
    } else if (this.Mangled.nextIf('i')) {
      entityKind = K.Initializer;
    } else {
      return NONE;
    }
    hasType = false;
  } else {
    entityKind = entityBasicKind;
    name = this.demangleDeclName(depth + 1);
    if (!name) return NONE;
  }

  let entity = this.Factory.createNode(entityKind);
  if (wrapEntity) {
    // Create a subscript or variable node and make it the accessor's child
    let wrappedEntity;
    let isSubscript = false;

    // Rewrite the subscript's name to match the new mangling scheme
    switch (name.getKind()) {
      case K.Identifier:
        if (name.getText() == "subscript") {
          isSubscript = true;
          // Subscripts have no 'subscript' identifier name
          name = NONE;
        }
        break;
      case K.PrivateDeclName: // identifier file-discriminator?
        if (name.getNumChildren() > 1 &&
            name.getChild(1).getText() == "subscript") {
          isSubscript = true;

          let discriminator = name.getChild(0);

          // Create new PrivateDeclName with no 'subscript' identifier child
          name = this.Factory.createNode(K.PrivateDeclName);
          name.addChild(discriminator);
        }
        break;
      default:
        break;
    }

    // Create wrapped entity node
    if (isSubscript) {
      wrappedEntity = this.Factory.createNode(K.Subscript);
    } else {
      wrappedEntity = this.Factory.createNode(K.Variable);
    }
    wrappedEntity.addChild(context);

    // Variables mangle their name before their type
    if (!isSubscript)
      wrappedEntity.addChild(name);

    if (hasType) {
      let type = this.demangleType(depth + 1);
      if (!type) return NONE;
      wrappedEntity.addChild(type);
    }

    // Subscripts mangle their file-discriminator after the type
    if (isSubscript && name)
      wrappedEntity.addChild(name);

    entity.addChild(wrappedEntity);
  } else {
    entity.addChild(context);

    if (name) entity.addChild(name);

    if (hasType) {
      let type = this.demangleType(depth + 1);
      if (!type) return NONE;
      entity.addChild(type);
    }
  }
  
  if (isStatic) {
    let staticNode = this.Factory.createNode(K.Static);
    staticNode.addChild(entity);
    return staticNode;
  }

  return entity;
}

  getDependentGenericParamType(depth: number, index: number): Node {

  let paramTy = this.Factory.createNode(K.DependentGenericParamType);
  paramTy.addChild(this.Factory.createNode(K.Index, depth));
  paramTy.addChild(this.Factory.createNode(K.Index, index));

  return paramTy;
}

  demangleGenericParamIndex(depth: number): Node {
  let paramDepth = 0, index = 0;

  if (this.Mangled.nextIf('d')) {
    if (!((paramDepth = this.demangleIndexV(depth + 1)) >= 0))
      return NONE;
    paramDepth += 1;
    if (!((index = this.demangleIndexV(depth + 1)) >= 0))
      return NONE;
  } else if (this.Mangled.nextIf('x')) {
    paramDepth = 0;
    index = 0;
  } else {
    if (!((index = this.demangleIndexV(depth + 1)) >= 0))
      return NONE;
    paramDepth = 0;
    index += 1;
  }
  return this.getDependentGenericParamType(paramDepth, index);
}

  demangleDependentMemberTypeName(base: Node, depth: number): Node {
  /* assert */ void 0;
  let assocTy = NONE;

  if (this.Mangled.nextIf('S')) {
    assocTy = this.demangleSubstitutionIndex(depth + 1);
    if (!assocTy)
      return NONE;
    if (assocTy.getKind() != K.DependentAssociatedTypeRef)
      return NONE;
  } else {
    let protocol = NONE;
    if (this.Mangled.nextIf('P')) {
      protocol = this.demangleProtocolName(depth + 1);
      if (!protocol) return NONE;
    }

    // TODO: If the protocol name was elided from the assoc type mangling,
    // we could try to fish it out of the generic signature constraints on the
    // base.
    let ID = this.demangleIdentifier(depth + 1);
    if (!ID) return NONE;
    assocTy = this.Factory.createNode(K.DependentAssociatedTypeRef);
    if (!assocTy) return NONE;
    assocTy.addChild(ID);
    if (protocol)
      assocTy.addChild(protocol);

    this.Substitutions.push(assocTy);
  }

  let depTy = this.Factory.createNode(K.DependentMemberType);
  depTy.addChild(base);
  depTy.addChild(assocTy);
  return depTy;
}

  demangleAssociatedTypeSimple(depth: number): Node {
  // Demangle the base type.
  let base = this.demangleGenericParamIndex(depth + 1);
  if (!base)
    return NONE;

  let nodeType = this.Factory.createNode(K.Type);
  nodeType.addChild(base);

  // Demangle the associated type name.
  return this.demangleDependentMemberTypeName(nodeType, depth + 1);
}

  demangleAssociatedTypeCompound(depth: number): Node {
  // Demangle the base type.
  let base = this.demangleGenericParamIndex(depth + 1);
  if (!base)
    return NONE;

  // Demangle the associated type chain.
  while (!this.Mangled.nextIf('_')) {
    let nodeType = this.Factory.createNode(K.Type);
    nodeType.addChild(base);

    base = this.demangleDependentMemberTypeName(nodeType, depth + 1);
    if (!base)
      return NONE;
  }

  return base;
}

  demangleDependentType(depth: number): Node {
  if (this.Mangled.isEmpty())
    return NONE;

  // A dependent member type begins with a non-index, non-'d' character.
  let c = this.Mangled.peek();
  if (c != 'd' && c != '_' && !N.isDigit(c)) {
    let baseType = this.demangleType(depth + 1);
    if (!baseType) return NONE;
    return this.demangleDependentMemberTypeName(baseType, depth + 1);
  }
  
  // Otherwise, we have a generic parameter.
  return this.demangleGenericParamIndex(depth + 1);
}

  demangleConstrainedTypeImpl(depth: number): Node {
  // The constrained type can only be a generic parameter or an associated
  // type thereof. The 'q' introducer is thus left off of generic params.
  if (this.Mangled.nextIf('w')) {
    return this.demangleAssociatedTypeSimple(depth + 1);
  }
  if (this.Mangled.nextIf('W')) {
    return this.demangleAssociatedTypeCompound(depth + 1);
  }
  return this.demangleGenericParamIndex(depth + 1);
}

  demangleConstrainedType(depth: number): Node {
  let type = this.demangleConstrainedTypeImpl(depth);
  if (!type)
    return NONE;

  let nodeType = this.Factory.createNode(K.Type);
  nodeType.addChild(type);
  return nodeType;
}

  demangleGenericSignature(depth: number, isPseudogeneric: boolean = false): Node {
  let sig =
    this.Factory.createNode(isPseudogeneric
                          ? K.DependentPseudogenericSignature
                          : K.DependentGenericSignature);
  // First read in the parameter counts at each depth.
  let count = -1;
  
  let addCount = () => {
    let countNode =
      this.Factory.createNode(K.DependentGenericParamCount, count);
    sig.addChild(countNode);
  };
  
  while (this.Mangled.peek() != 'R' && this.Mangled.peek() != 'r') {
    if (this.Mangled.nextIf('z')) {
      count = 0;
    } else if (((count = this.demangleIndexV(depth + 1)) >= 0)) {
      count += 1;
    } else {
      return NONE;
    }
    addCount();
  }
  
  // No mangled parameters means we have exactly one.
  if (count == -1) {
    count = 1;
    addCount();
  }
  
  // Next read in the generic requirements, if any.
  if (this.Mangled.nextIf('r'))
    return sig;
  
  if (!this.Mangled.nextIf('R'))
    return NONE;
  
  while (!this.Mangled.nextIf('r')) {
    let reqt = this.demangleGenericRequirement(depth + 1);
    if (!reqt) return NONE;
    sig.addChild(reqt);
  }
  
  return sig;
}

  demangleMetatypeRepresentation(depth: number): Node {
  if (this.Mangled.nextIf('t'))
    return this.Factory.createNode(K.MetatypeRepresentation, "@thin");

  if (this.Mangled.nextIf('T'))
    return this.Factory.createNode(K.MetatypeRepresentation, "@thick");

  if (this.Mangled.nextIf('o'))
    return this.Factory.createNode(K.MetatypeRepresentation,
                               "@objc_metatype");

  // Unknown metatype representation
  return NONE;
}

  demangleGenericRequirement(depth: number): Node {
  let constrainedType = this.demangleConstrainedType(depth + 1);
  if (!constrainedType)
    return NONE;
  if (this.Mangled.nextIf('z')) {
    let second = this.demangleType(depth + 1);
    if (!second) return NONE;
    let reqt = this.Factory.createNode(
        K.DependentGenericSameTypeRequirement);
    reqt.addChild(constrainedType);
    reqt.addChild(second);
    return reqt;
  }

  if (this.Mangled.nextIf('l')) {
    let name = '';
    let kind: Kind;
    let size = -1;
    let alignment = -1;
    if (this.Mangled.nextIf('U')) {
      kind = K.Identifier;
      name = "U";
    } else if (this.Mangled.nextIf('R')) {
      kind = K.Identifier;
      name = "R";
    } else if (this.Mangled.nextIf('N')) {
      kind = K.Identifier;
      name = "N";
    } else if (this.Mangled.nextIf('T')) {
      kind = K.Identifier;
      name = "T";
    } else if (this.Mangled.nextIf('B')) {
      kind = K.Identifier;
      name = "B";
    } else if (this.Mangled.nextIf('E')) {
      kind = K.Identifier;
      if (!((size = this.demangleNaturalV(depth + 1)) >= 0))
        return NONE;
      if (!this.Mangled.nextIf('_'))
        return NONE;
      if (!((alignment = this.demangleNaturalV(depth + 1)) >= 0))
        return NONE;
      name = "E";
    } else if (this.Mangled.nextIf('e')) {
      kind = K.Identifier;
      if (!((size = this.demangleNaturalV(depth + 1)) >= 0))
        return NONE;
      name = "e";
    } else if (this.Mangled.nextIf('M')) {
      kind = K.Identifier;
      if (!((size = this.demangleNaturalV(depth + 1)) >= 0))
        return NONE;
      if (!this.Mangled.nextIf('_'))
        return NONE;
      if (!((alignment = this.demangleNaturalV(depth + 1)) >= 0))
        return NONE;
      name = "M";
    } else if (this.Mangled.nextIf('m')) {
      kind = K.Identifier;
      if (!((size = this.demangleNaturalV(depth + 1)) >= 0))
        return NONE;
      name = "m";
    } else if (this.Mangled.nextIf('S')) {
      kind = K.Identifier;
      if (!((size = this.demangleNaturalV(depth + 1)) >= 0))
        return NONE;
      name = "S";
    } else {
      return NONE;
    }

    let second = this.Factory.createNode(kind, name);
    if (!second) return NONE;
    let reqt = this.Factory.createNode(
      K.DependentGenericLayoutRequirement);
    reqt.addChild(constrainedType);
    reqt.addChild(second);
    if (size >= 0) {
      reqt.addChild(this.Factory.createNode(K.Number, size));
      if (alignment >= 0)
        reqt.addChild(this.Factory.createNode(K.Number, alignment));
    }
    return reqt;
  }

  // Base class constraints are introduced by a class type mangling, which
  // will begin with either 'C' or 'S'.
  if (this.Mangled.isEmpty())
    return NONE;
  let constraint = NONE;

  let next = this.Mangled.peek();

  if (next == 'C') {
    constraint = this.demangleType(depth + 1);
    if (!constraint) return NONE;
  } else if (next == 'S') {
    // A substitution may be either the module name of a protocol or a full
    // type name.
    let typeName = NONE;
    this.Mangled.next();
    let sub = this.demangleSubstitutionIndex(depth + 1);
    if (!sub) return NONE;
    if (sub.getKind() == K.Protocol
        || sub.getKind() == K.Class) {
      typeName = sub;
    } else if (sub.getKind() == K.Module) {
      typeName = this.demangleProtocolNameGivenContext(sub, depth + 1);
      if (!typeName)
        return NONE;
    } else {
      return NONE;
    }
    constraint = this.Factory.createNode(K.Type);
    constraint.addChild(typeName);
  } else {
    constraint = this.demangleProtocolName(depth + 1);
    if (!constraint)
      return NONE;
  }
  let reqt = this.Factory.createNode(
                        K.DependentGenericConformanceRequirement);
  reqt.addChild(constrainedType);
  reqt.addChild(constraint);
  return reqt;
}

  demangleArchetypeType(depth: number): Node {
  let makeAssociatedType = (root: Node): Node => {
    let name = this.demangleIdentifier(depth + 1);
    if (!name)
      return NONE;
    let assocType = this.Factory.createNode(K.AssociatedTypeRef);
    assocType.addChild(root);
    assocType.addChild(name);
    this.Substitutions.push(assocType);
    return assocType;
  };

  if (this.Mangled.nextIf('Q')) {
    let root = this.demangleArchetypeType(depth + 1);
    if (!root) return NONE;
    return makeAssociatedType(root);
  }
  if (this.Mangled.nextIf('S')) {
    let sub = this.demangleSubstitutionIndex(depth + 1);
    if (!sub) return NONE;
    return makeAssociatedType(sub);
  }
  if (this.Mangled.nextIf('s')) {
    let stdlib = this.Factory.createNode(K.Module, STDLIB_NAME);
    return makeAssociatedType(stdlib);
  }
  return NONE;
}

  demangleTuple(isV: boolean, depth: number): Node {
  let tuple = this.Factory.createNode(K.Tuple);
  let elt = NONE;
  while (!this.Mangled.nextIf('_')) {
    if (this.Mangled.isEmpty())
      return NONE;
    elt = this.Factory.createNode(K.TupleElement);

    if (isStartOfIdentifier(this.Mangled.peek())) {
      let label =
          this.demangleIdentifier(depth + 1, K.TupleElementName);
      if (!label)
        return NONE;
      elt.addChild(label);
    }

    let type = this.demangleType(depth + 1);
    if (!type)
      return NONE;
    elt.addChild(type);

    tuple.addChild(elt);
  }
  if (isV && elt) {
    elt.reverseChildren();
    let marker = this.Factory.createNode(K.VariadicMarker);
    elt.addChild(marker);
    elt.reverseChildren();
  }
  return tuple;
}

  postProcessReturnTypeNode(out_args: Node): Node {
  let out_node = this.Factory.createNode(K.ReturnType);
  out_node.addChild(out_args);
  return out_node;
}

  demangleType(depth: number): Node {
  let type = this.demangleTypeImpl(depth);
  if (!type)
    return NONE;
  let nodeType = this.Factory.createNode(K.Type);
  nodeType.addChild(type);
  return nodeType;
}

  demangleFunctionType(kind: Kind, depth: number): Node {
  let throws = false, concurrent = false, async = false;
  let diffKind = 0;
  let globalActorType = NONE;
  if (!this.Mangled.isEmpty()) {
    throws = this.Mangled.nextIf('z');
    concurrent = this.Mangled.nextIf('y');
    async = this.Mangled.nextIf('Z');
    if (this.Mangled.nextIf('D')) {
      const dk = this.Mangled.next();
      switch (dk) {
      case 'f': case 'r': case 'd': case 'l':
        diffKind = charCode(dk);
        break;
      default:
        break;
      }
    }
    if (this.Mangled.nextIf('Y')) {
      globalActorType = this.demangleType(depth + 1);
      if (!globalActorType)
        return NONE;
    }
  }
  let in_args = this.demangleType(depth + 1);
  if (!in_args)
    return NONE;
  let out_args = this.demangleType(depth + 1);
  if (!out_args)
    return NONE;
  let block = this.Factory.createNode(kind);
  
  if (throws) {
    block.addChild(this.Factory.createNode(K.ThrowsAnnotation));
  }
  if (async) {
    block.addChild(this.Factory.createNode(K.AsyncAnnotation));
  }
  if (concurrent) {
    block.addChild(
        this.Factory.createNode(K.ConcurrentFunctionType));
  }
  if (diffKind != 0) {
    block.addChild(
        this.Factory.createNode(
            K.DifferentiableFunctionType, diffKind));
  }
  if (globalActorType) {
    let globalActorNode =
        this.Factory.createNode(K.GlobalActorFunctionType);
    globalActorNode.addChild(globalActorType);
    block.addChild(globalActorNode);
  }
  // Is there any need to handle isolated(any) function types here?

  let in_node = this.Factory.createNode(K.ArgumentTuple);
  block.addChild(in_node);
  in_node.addChild(in_args);
  block.addChild(this.postProcessReturnTypeNode(out_args));
  return block;
}

  demangleTypeImpl(depth: number): Node {
  if (depth > OldDemangler.MaxDepth || this.Mangled.isEmpty())
    return NONE;
  let c = this.Mangled.next();
  if (c == 'B') {
    if (this.Mangled.isEmpty())
      return NONE;
    c = this.Mangled.next();
    if (c == 'b')
      return this.Factory.createNode(K.BuiltinTypeName,
                                   "Builtin.BridgeObject");
    if (c == 'B')
      return this.Factory.createNode(K.BuiltinTypeName,
                                   "Builtin.UnsafeValueBuffer");
    if (c == 'f') {
      let size = 0;
      if (((size = this.demangleBuiltinSizeV(depth + 1)) >= 0)) {
        return this.Factory.createNode(
            K.BuiltinTypeName,
            `Builtin.FPIEEE${size}`);
      }
    }
    if (c == 'i') {
      let size = 0;
      if (((size = this.demangleBuiltinSizeV(depth + 1)) >= 0)) {
        return this.Factory.createNode(
            K.BuiltinTypeName,
            `Builtin.Int${size}`);
      }
    }
    if (c == 'v') {
      let elts = 0;
      if (((elts = this.demangleNaturalV(depth + 1)) >= 0)) {
        if (!this.Mangled.nextIf('B'))
          return NONE;
        if (this.Mangled.nextIf('i')) {
          let size = 0;
          if (!((size = this.demangleBuiltinSizeV(depth + 1)) >= 0))
            return NONE;
          return this.Factory.createNode(
              K.BuiltinTypeName,
              `Builtin.Vec${elts}xInt${size}`
                  );
        }
        if (this.Mangled.nextIf('f')) {
          let size = 0;
          if (!((size = this.demangleBuiltinSizeV(depth + 1)) >= 0))
            return NONE;
          return this.Factory.createNode(
              K.BuiltinTypeName,
              `Builtin.Vec${elts}xFPIEEE${size}`);
        }
        if (this.Mangled.nextIf('p'))
          return this.Factory.createNode(
              K.BuiltinTypeName,
              `Builtin.Vec${elts}xRawPointer`
                  );
      }
    }
    if (c == 'O')
      return this.Factory.createNode(K.BuiltinTypeName,
                                   "Builtin.UnknownObject");
    if (c == 'o')
      return this.Factory.createNode(K.BuiltinTypeName,
                                   "Builtin.NativeObject");
    if (c == 'p')
      return this.Factory.createNode(K.BuiltinTypeName,
                                   "Builtin.RawPointer");
    if (c == 't')
      return this.Factory.createNode(K.BuiltinTypeName,
                                   "Builtin.SILToken");
    if (c == 'w')
      return this.Factory.createNode(K.BuiltinTypeName,
                                   "Builtin.Word");
    return NONE;
  }
  if (c == 'a')
    return this.demangleDeclarationName(K.TypeAlias, depth + 1);

  if (c == 'b') {
    return this.demangleFunctionType(K.ObjCBlock, depth + 1);
  }
  if (c == 'c') {
    return this.demangleFunctionType(K.CFunctionPointer, depth + 1);
  }
  if (c == 'D') {
    let type = this.demangleType(depth + 1);
    if (!type)
      return NONE;

    let dynamicSelf = this.Factory.createNode(K.DynamicSelf);
    dynamicSelf.addChild(type);
    return dynamicSelf;
  }
  if (c == 'E') {
    if (!this.Mangled.nextIf('R'))
      return NONE;
    if (!this.Mangled.nextIf('R'))
      return NONE;
    return this.Factory.createNode(K.ErrorType, '');
  }
  if (c == 'F') {
    return this.demangleFunctionType(K.FunctionType, depth + 1);
  }
  if (c == 'f') {
    return this.demangleFunctionType(K.UncurriedFunctionType, depth + 1);
  }
  if (c == 'G') {
    return this.demangleBoundGenericType(depth + 1);
  }
  if (c == 'X') {
    if (this.Mangled.nextIf('b')) {
      let type = this.demangleType(depth + 1);
      if (!type)
        return NONE;
      let boxType = this.Factory.createNode(K.SILBoxType);
      boxType.addChild(type);
      return boxType;
    }
    if (this.Mangled.nextIf('B')) {
      let signature = NONE;
      if (this.Mangled.nextIf('G')) {
        signature = this.demangleGenericSignature(depth, /*pseudogeneric*/ false);
        if (!signature)
          return NONE;
      }
      let layout = this.Factory.createNode(K.SILBoxLayout);
      while (!this.Mangled.nextIf('_')) {
        let kind;
        if (this.Mangled.nextIf('m'))
          kind = K.SILBoxMutableField;
        else if (this.Mangled.nextIf('i'))
          kind = K.SILBoxImmutableField;
        else
          return NONE;

        let type = this.demangleType(depth + 1);
        if (!type)
          return NONE;
        let field = this.Factory.createNode(kind);
        field.addChild(type);
        layout.addChild(field);
      }
      let genericArgs = NONE;
      if (signature) {
        genericArgs = this.Factory.createNode(K.TypeList);
        while (!this.Mangled.nextIf('_')) {
          let type = this.demangleType(depth + 1);
          if (!type)
            return NONE;
          genericArgs.addChild(type);
        }
      }
      let boxType =
        this.Factory.createNode(K.SILBoxTypeWithLayout);
      boxType.addChild(layout);
      if (signature) {
        boxType.addChild(signature);
        /* assert */ void 0;
        boxType.addChild(genericArgs);
      }
      return boxType;
    }
  }
  if (c == 'K') {
    return this.demangleFunctionType(K.AutoClosureType, depth + 1);
  }
  if (c == 'M') {
    let type = this.demangleType(depth + 1);
    if (!type)
      return NONE;
    let metatype = this.Factory.createNode(K.Metatype);
    metatype.addChild(type);
    return metatype;
  }
  if (c == 'X') {
    if (this.Mangled.nextIf('M')) {
      let metatypeRepr = this.demangleMetatypeRepresentation(depth + 1);
      if (!metatypeRepr) return NONE;

      let type = this.demangleType(depth + 1);
      if (!type)
        return NONE;
      let metatype = this.Factory.createNode(K.Metatype);
      metatype.addChild(metatypeRepr);
      metatype.addChild(type);
      return metatype;
    }
  }
  if (c == 'P') {
    if (this.Mangled.nextIf('M')) {
      let type = this.demangleType(depth + 1);
      if (!type) return NONE;
      let metatype = this.Factory.createNode(K.ExistentialMetatype);
      metatype.addChild(type);
      return metatype;
    }

    return this.demangleProtocolList(depth + 1);
  }

  if (c == 'X') {
    if (this.Mangled.nextIf('P')) {
      if (this.Mangled.nextIf('M')) {
        let metatypeRepr = this.demangleMetatypeRepresentation(depth + 1);
        if (!metatypeRepr) return NONE;

        let type = this.demangleType(depth + 1);
        if (!type) return NONE;

        let metatype = this.Factory.createNode(K.ExistentialMetatype);
        metatype.addChild(metatypeRepr);
        metatype.addChild(type);
        return metatype;
      }

      return this.demangleProtocolList(depth + 1);
    }
  }
  if (c == 'Q') {
    if (this.Mangled.nextIf('u')) {
      // Special mangling for opaque return type.
      return this.Factory.createNode(K.OpaqueReturnType);
    }
    if (this.Mangled.nextIf('U')) {
      // Special mangling for opaque return type.
      let ordinal = 0;
      if (!((ordinal = this.demangleIndexV(depth)) >= 0))
        return NONE;
      let result = this.Factory.createNode(K.OpaqueReturnType);
      result.addChild(
        this.Factory.createNode(K.OpaqueReturnTypeIndex, ordinal));
      return result;
    }
    return this.demangleArchetypeType(depth + 1);
  }
  if (c == 'q') {
    return this.demangleDependentType(depth + 1);
  }
  if (c == 'x') {
    // Special mangling for the first generic param.
    return this.getDependentGenericParamType(0, 0);
  }
  if (c == 'w') {
    return this.demangleAssociatedTypeSimple(depth + 1);
  }
  if (c == 'W') {
    return this.demangleAssociatedTypeCompound(depth + 1);
  }
  if (c == 'R') {
    let inout = this.Factory.createNode(K.InOut);
    let type = this.demangleTypeImpl(depth + 1);
    if (!type)
      return NONE;
    inout.addChild(type);
    return inout;
  }
  if (c == 'k') {
    let noDerivative = this.Factory.createNode(K.NoDerivative);
    let type = this.demangleTypeImpl(depth + 1);
    if (!type)
      return NONE;
    noDerivative.addChild(type);
    return noDerivative;
  }
  if (c == 'S') {
    return this.demangleSubstitutionIndex(depth + 1);
  }
  if (c == 'T') {
    return this.demangleTuple(false, depth + 1);
  }
  if (c == 't') {
    return this.demangleTuple(true, depth + 1);
  }
  if (c == 'u') {
    let sig = this.demangleGenericSignature(depth + 1);
    if (!sig) return NONE;
    let sub = this.demangleType(depth + 1);
    if (!sub) return NONE;
    let dependentGenericType = this.Factory.createNode(K.DependentGenericType);
    dependentGenericType.addChild(sig);
    dependentGenericType.addChild(sub);
    return dependentGenericType;
  }
  if (c == 'X') {
    if (this.Mangled.nextIf('f')) {
      return this.demangleFunctionType(K.ThinFunctionType, depth + 1);
    }
    if (this.Mangled.nextIf('o')) {
      let type = this.demangleType(depth + 1);
      if (!type)
        return NONE;
      let unowned = this.Factory.createNode(K.Unowned);
      unowned.addChild(type);
      return unowned;
    }
    if (this.Mangled.nextIf('u')) {
      let type = this.demangleType(depth + 1);
      if (!type)
        return NONE;
      let unowned = this.Factory.createNode(K.Unmanaged);
      unowned.addChild(type);
      return unowned;
    }
    if (this.Mangled.nextIf('w')) {
      let type = this.demangleType(depth + 1);
      if (!type)
        return NONE;
      let weak = this.Factory.createNode(K.Weak);
      weak.addChild(type);
      return weak;
    }

    // type ::= 'XF' impl-function-type
    if (this.Mangled.nextIf('F')) {
      return this.demangleImplFunctionType(depth + 1);
    }

    return NONE;
  }
  if (isStartOfNominalType(c))
    return this.demangleDeclarationName(nominalTypeMarkerToNodeKind(c), depth + 1);
  return NONE;
}

  demangleReabstractSignature(signature: Node, depth: number): boolean {
  if (this.Mangled.nextIf('G')) {
    let generics = this.demangleGenericSignature(depth + 1);
    if (!generics) return false;
    signature.addChild(generics);
  }

  let srcType = this.demangleType(depth + 1);
  if (!srcType) return false;
  signature.addChild(srcType);

  let destType = this.demangleType(depth + 1);
  if (!destType) return false;
  signature.addChild(destType);

  return true;
}


  demangleImplFunctionType(depth: number): Node {
  let type = this.Factory.createNode(K.ImplFunctionType);

  if (!this.demangleImplCalleeConvention(type, depth + 1))
    return NONE;

  if (this.Mangled.nextIf('C')) {
    if (this.Mangled.nextIf('b'))
      this.addImplFunctionConvention(type, "block");
    else if (this.Mangled.nextIf('c'))
      this.addImplFunctionConvention(type, "c");
    else if (this.Mangled.nextIf('m'))
      this.addImplFunctionConvention(type, "method");
    else if (this.Mangled.nextIf('O'))
      this.addImplFunctionConvention(type, "objc_method");
    else if (this.Mangled.nextIf('w'))
      this.addImplFunctionConvention(type, "witness_method");
    else
      return NONE;
  }

  if (this.Mangled.nextIf('h'))
    this.addImplFunctionAttribute(type, "@Sendable");

  if (this.Mangled.nextIf('H'))
    this.addImplFunctionAttribute(type, "@async");

  // Enter a new generic context if this type is generic.
  // FIXME: replace with optional, when we have it.
  let isPseudogeneric = false;
  if (this.Mangled.nextIf('G') ||
      (isPseudogeneric = this.Mangled.nextIf('g'))) {
    let generics =
        this.demangleGenericSignature(depth + 1, isPseudogeneric);
    if (!generics)
      return NONE;
    type.addChild(generics);
  }

  // Expect the attribute terminator.
  if (!this.Mangled.nextIf('_'))
    return NONE;

  // Demangle the parameters.
  if (!this.demangleImplParameters(type, depth + 1))
    return NONE;

  // Demangle the result type.
  if (!this.demangleImplResults(type, depth + 1))
    return NONE;

  return type;
}


  demangleImplConvention(ctxt: number, _depth: number): string {
  // [char, callee, parameter, result]
  const table: [string, string, string, string][] = [
    ['a', '', '', '@autoreleased'],
    ['d', '@callee_unowned', '@unowned', '@unowned'],
    ['D', '', '', '@unowned_inner_pointer'],
    ['g', '@callee_guaranteed', '@guaranteed', ''],
    ['e', '', '@deallocating', ''],
    ['i', '', '@in', '@out'],
    ['l', '', '@inout', ''],
    ['o', '@callee_owned', '@owned', '@owned'],
  ];
  for (const row of table) {
    if (this.Mangled.nextIf(row[0])) return row[1 + ctxt]!;
  }
  return '';
}

  demangleImplCalleeConvention(type: Node, depth: number): boolean {
  let attr;
  if (this.Mangled.nextIf('t')) {
    attr = "@convention(thin)";
  } else {
    attr = this.demangleImplConvention(0, depth + 1);
  }
  if (attr.length === 0) {
    return false;
  }
  type.addChild(this.Factory.createNode(K.ImplConvention, attr));
  return true;
}

  addImplFunctionAttribute(parent: Node, attr: string, kind: Kind = K.ImplFunctionAttribute): void {
  parent.addChild(this.Factory.createNode(kind, attr));
}

  addImplFunctionConvention(parent: Node, attr: string): void {
  let attrNode = this.Factory.createNode(K.ImplFunctionConvention);
  attrNode.addChild(
      this.Factory.createNode(K.ImplFunctionConventionName, attr));
  parent.addChild(attrNode);
}


  demangleImplParameters(parent: Node, depth: number): boolean {
  while (!this.Mangled.nextIf('_')) {
    let input =
        this.demangleImplParameterOrResult(K.ImplParameter, depth + 1);
    if (!input) return false;
    parent.addChild(input);
  }
  return true;
}


  demangleImplResults(parent: Node, depth: number): boolean {
  while (!this.Mangled.nextIf('_')) {
    let res =
        this.demangleImplParameterOrResult(K.ImplResult, depth + 1);
    if (!res) return false;
    parent.addChild(res);
  }
  return true;
}

  demangleImplParameterOrResult(kind: Kind, depth: number): Node {
  if (this.Mangled.nextIf('z')) {
    // Only valid for a result.
    if (kind != K.ImplResult)
      return NONE;
    kind = K.ImplErrorResult;
  }

  let ConvCtx: number;
  if (kind == K.ImplParameter) {
    ConvCtx = 1;
  } else if (kind == K.ImplResult
             || kind == K.ImplErrorResult) {
    ConvCtx = 2;
  } else {
    return NONE;
  }

  let convention = this.demangleImplConvention(ConvCtx, depth + 1);
  if (convention.length === 0) return NONE;
  let type = this.demangleType(depth + 1);
  if (!type) return NONE;

  let node = this.Factory.createNode(kind);
  node.addChild(this.Factory.createNode(K.ImplConvention, convention));
  node.addChild(type);

  return node;
}

}

/** Demangle an old-style (_T) Swift symbol into a node tree, or NONE. */
export function demangleOldSymbolAsNode(MangledName: string, factory: Factory): Node {
  return new OldDemangler(MangledName, factory).demangleTopLevel();
}
