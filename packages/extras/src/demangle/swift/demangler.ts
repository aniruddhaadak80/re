// Swift symbol demangler (new mangling: $s, $S, _T0, @__swiftmacro_). Ported from
// swift/lib/Demangling/Demangler.cpp (swift-6.0.3-RELEASE), Copyright (c) 2014-2024 Apple Inc. and the
// Swift project authors, Apache License v2.0 with Runtime Library Exception. See README for credit.

import {
  Node, NONE, K, type Kind, DemangleError, isContext, isDigit, isLowerLetter, isUpperLetter, isLetter, isWordStart, isWordEnd,
  FunctionSigSpecializationParamKind,
  VALUE_WITNESSES, STDLIB_NAME, MANGLING_MODULE_OBJC, MANGLING_MODULE_CLANG_IMPORTER, charCode,
} from './nodes.js';
import * as N from './nodes.js';
import { decodePunycodeString } from './punycode.js';
import { demangleOldSymbolAsNode } from './old.js';

const MAX_NODES = 100000;

export class Demangler {
  Text = '';
  Pos = 0;
  IsOldFunctionTypeMangling = false;
  NodeStack: Node[] = [];
  Substitutions: Node[] = [];
  static readonly MaxNumWords = 26;
  Words: string[] = [];
  NumWords = 0;
  nodeCount = 0;
  depth = 0;

  nextIfStr(str: string): boolean { if (!this.Text.startsWith(str, this.Pos)) return false; this.Pos += str.length; return true; }
  peekChar(): string { return this.Pos >= this.Text.length ? '\0' : this.Text[this.Pos]!; }
  nextChar(): string { return this.Pos >= this.Text.length ? '\0' : this.Text[this.Pos++]!; }
  nextIf(c: string): boolean { if (c.length !== 1) return this.nextIfStr(c); if (this.peekChar() !== c) return false; this.Pos++; return true; }
  pushBack(): void { if (this.Pos > 0) this.Pos--; }
  consumeAll(): string { const s = this.Text.slice(this.Pos); this.Pos = this.Text.length; return s; }
  pushNode(n: Node): void { this.NodeStack.push(n); }
  popNode(k?: Kind | ((k: Kind) => boolean)): Node {
    if (!this.NodeStack.length) return NONE;
    if (k !== undefined) {
      const top = this.NodeStack[this.NodeStack.length - 1]!.getKind();
      if (typeof k === 'function' ? !k(top) : top !== k) return NONE;
    }
    return this.NodeStack.pop()!;
  }
  addSubstitution(n: Node): void { if (n) this.Substitutions.push(n); }
  createNode(k: Kind, payload?: string | number): Node {
    if (++this.nodeCount > MAX_NODES) throw new DemangleError('too many nodes');
    return new Node(k, payload);
  }
  createNodeWithAllocatedText(k: Kind, t: string): Node { return this.createNode(k, t); }
  createWithPoppedType(k: Kind): Node { return this.createWithChild(k, this.popNode(K.Type)); }
  createWithChildren(kind: Kind, ...cs: Node[]): Node {
    for (const c of cs) if (!c) return NONE;
    const n = this.createNode(kind);
    for (const c of cs) n.addChild(c);
    return n;
  }
  isDeclName(kind: Kind): boolean {
  switch (kind) {
    case K.Identifier:
    case K.LocalDeclName:
    case K.PrivateDeclName:
    case K.RelatedEntityDeclName:
    case K.PrefixOperator:
    case K.PostfixOperator:
    case K.InfixOperator:
    case K.TypeSymbolicReference:
    case K.ProtocolSymbolicReference:
    case K.ObjectiveCProtocolSymbolicReference:
      return true;
    default:
      return false;
  }
}

  isAnyGeneric(kind: Kind): boolean {
  switch (kind) {
    case K.Structure:
    case K.Class:
    case K.Enum:
    case K.Protocol:
    case K.ProtocolSymbolicReference:
    case K.ObjectiveCProtocolSymbolicReference:
    case K.OtherNominalType:
    case K.TypeAlias:
    case K.TypeSymbolicReference:
    case K.BuiltinTupleType:
      return true;
    default:
      return false;
  }
}

  isEntity(kind: Kind): boolean {
  // Also accepts some kind which are not entities.
  if (kind == K.Type)
    return true;
  return isContext(kind);
}

  isRequirement(kind: Kind): boolean {
  switch (kind) {
    case K.DependentGenericParamPackMarker:
    case K.DependentGenericSameTypeRequirement:
    case K.DependentGenericSameShapeRequirement:
    case K.DependentGenericLayoutRequirement:
    case K.DependentGenericConformanceRequirement:
    case K.DependentGenericInverseConformanceRequirement:
      return true;
    default:
      return false;
  }
}




  isProtocolNode(Node: Node): boolean {
  switch (Node.getKind()) {
  case K.Type:
    return this.isProtocolNode(Node.getChild(0));
  case K.Protocol:
  case K.ProtocolSymbolicReference:
  case K.ObjectiveCProtocolSymbolicReference:
    return true;
  default:
    return false;
  }
}

  isFunctionAttr(kind: Kind): boolean {
  switch (kind) {
    case K.FunctionSignatureSpecialization:
    case K.GenericSpecialization:
    case K.GenericSpecializationPrespecialized:
    case K.InlinedGenericFunction:
    case K.GenericSpecializationNotReAbstracted:
    case K.GenericPartialSpecialization:
    case K.GenericPartialSpecializationNotReAbstracted:
    case K.GenericSpecializationInResilienceDomain:
    case K.ObjCAttribute:
    case K.NonObjCAttribute:
    case K.DynamicAttribute:
    case K.DirectMethodReferenceAttribute:
    case K.VTableAttribute:
    case K.PartialApplyForwarder:
    case K.PartialApplyObjCForwarder:
    case K.OutlinedVariable:
    case K.OutlinedReadOnlyObject:
    case K.OutlinedBridgedMethod:
    case K.MergedFunction:
    case K.DistributedThunk:
    case K.DistributedAccessor:
    case K.DynamicallyReplaceableFunctionImpl:
    case K.DynamicallyReplaceableFunctionKey:
    case K.DynamicallyReplaceableFunctionVar:
    case K.AsyncFunctionPointer:
    case K.AsyncAwaitResumePartialFunction:
    case K.AsyncSuspendResumePartialFunction:
    case K.AccessibleFunctionRecord:
    case K.BackDeploymentThunk:
    case K.BackDeploymentFallback:
    case K.HasSymbolQuery:
      return true;
    default:
      return false;
  }
}


  getManglingPrefixLength(mangledName: string): number {
  if (mangledName.length === 0) return 0;

  const prefixes = [
    /*Swift 4*/   "_T0",
    /*Swift 4.x*/ "$S", "_$S",
    /*Swift 5+*/  "$s", "_$s",
    /*Swift 5+ for filenames*/ "@__swiftmacro_",
  ];

  // Look for any of the known prefixes
  for (const prefix of prefixes) {
    if (mangledName.startsWith(prefix))
      return prefix.length;
  }

  return 0;
}




  isOldFunctionTypeMangling(mangledName: string): boolean {
  return mangledName.startsWith("_T");
}














  demangleSymbol(MangledName: string): Node {
  this.Text = MangledName; this.Pos = 0; this.NodeStack = []; this.Substitutions = []; this.NumWords = 0; this.Words = [];

  // Demangle old-style class and protocol names, which are still used in the
  // ObjC metadata.
  if (this.nextIf("_Tt"))
    return demangleOldSymbolAsNode(this.Text, this);

  let PrefixLength = this.getManglingPrefixLength(MangledName);
  if (PrefixLength == 0)
    return NONE;

  this.IsOldFunctionTypeMangling = this.isOldFunctionTypeMangling(MangledName);
  this.Pos += PrefixLength;

  if (!this.parseAndPushNodes())
    return NONE;

  let topLevel = this.createNode(K.Global);

  let Parent = topLevel;
  let FuncAttr: Node;
  while ((FuncAttr = this.popNode(this.isFunctionAttr))) {
    Parent.addChild(FuncAttr);
    if (FuncAttr.getKind() == K.PartialApplyForwarder ||
        FuncAttr.getKind() == K.PartialApplyObjCForwarder)
      Parent = FuncAttr;
  }
  for (const Nd of this.NodeStack) {
    switch (Nd.getKind()) {
      case K.Type:
        Parent.addChild(Nd.getFirstChild());
        break;
      default:
        Parent.addChild(Nd);
        break;
    }
  }
  if (topLevel.getNumChildren() == 0)
    return NONE;

  return topLevel;
}

  demangleType(MangledName: string): Node {
  this.Text = MangledName; this.Pos = 0; this.NodeStack = []; this.Substitutions = []; this.NumWords = 0; this.Words = [];
  this.parseAndPushNodes();
  const Result = this.popNode();
  if (Result)
    return Result;
  return this.createNode(K.Suffix, this.Text);
}

  parseAndPushNodes(): boolean {
  let textSize = this.Text.length;
  while (this.Pos < textSize) {
    let Node = this.demangleOperator();
    if (!Node)
      return false;
    this.pushNode(Node);
  }
  return true;
}

  addChild(Parent: Node, Child: Node): Node {
  if (!Parent || !Child)
    return NONE;
  Parent.addChild(Child);
  return Parent;
}

  createWithChild(kind: Kind, Child: Node): Node {
  if (!Child)
    return NONE;
  let Nd = this.createNode(kind);
  Nd.addChild(Child);
  return Nd;
}

  createType(Child: Node): Node {
  return this.createWithChild(K.Type, Child);
}

  changeKind(Node: Node, NewKind: Kind): Node {
  if (!Node)
    return NONE;
  let NewNode: Node;
  if (Node.hasText()) {
    NewNode = this.createNodeWithAllocatedText(NewKind, Node.getText());
  } else if (Node.hasIndex()) {
    NewNode = this.createNode(NewKind, Node.getIndex());
  } else {
    NewNode = this.createNode(NewKind);
  }
  for (const Child of Node.children) {
    NewNode.addChild(Child);
  }
  return NewNode;
}

  demangleTypeMangling(): Node {
  let Type = this.popNode(K.Type);
  let LabelList = this.popFunctionParamLabels(Type);
  let TypeMangling = this.createNode(K.TypeMangling);

  this.addChild(TypeMangling, LabelList);
  TypeMangling = this.addChild(TypeMangling, Type);
  return TypeMangling;
}

  demangleSymbolicReference(_rawKind: string): Node {
    // Symbolic references are 4-byte relative offsets into a loaded image; without a resolver the
    // C++ demangler refuses to continue, and so do we.
    if (this.Pos + 4 > this.Text.length) return NONE;
    this.Pos += 4;
    return NONE;
  }

  demangleTypeAnnotation(): Node {
  switch (this.nextChar()) {
  case 'a':
    return this.createNode(K.AsyncAnnotation);
  case 'A':
    return this.createNode(K.IsolatedAnyFunctionType);
  case 'b':
    return this.createNode(K.ConcurrentFunctionType);
  case 'c':
    return this.createWithChild(
        K.GlobalActorFunctionType, this.popTypeAndGetChild());
  case 'i':
    return this.createType(
        this.createWithChild(K.Isolated, this.popTypeAndGetChild()));
  case 'j':
    return this.demangleDifferentiableFunctionType();
  case 'k':
    return this.createType(
        this.createWithChild(K.NoDerivative, this.popTypeAndGetChild()));
  case 'K':
    return this.createWithChild(K.TypedThrowsAnnotation, this.popTypeAndGetChild());
  case 't':
    return this.createType(
        this.createWithChild(K.CompileTimeConst, this.popTypeAndGetChild()));
  case 'T':
    return this.createNode(K.SendingResultFunctionType);
  case 'u':
    return this.createType(
        this.createWithChild(K.Sending, this.popTypeAndGetChild()));
  case 'l':
    return this.demangleLifetimeDependenceKind(/*isSelfDependence*/ false);
  case 'L':
    return this.demangleLifetimeDependenceKind(/*isSelfDependence*/ true);
  default:
    return NONE;
  }
}

  demangleOperator(): Node {
  let c = this.nextChar();
  // A 0xFF byte is used as alignment padding for symbolic references.
  while (c === '\xff') c = this.nextChar();
  if (c >= '\x01' && c <= '\x0c') return this.demangleSymbolicReference(c);
  switch (c) {
    case 'A': return this.demangleMultiSubstitutions();
    case 'B': return this.demangleBuiltinType();
    case 'C': return this.demangleAnyGenericType(K.Class);
    case 'D': return this.demangleTypeMangling();
    case 'E': return this.demangleExtensionContext();
    case 'F': return this.demanglePlainFunction();
    case 'G': return this.demangleBoundGenericType();
    case 'H':
      switch (this.nextChar()) {
      case 'A': return this.demangleDependentProtocolConformanceAssociated();
      case 'C': return this.demangleConcreteProtocolConformance();
      case 'D': return this.demangleDependentProtocolConformanceRoot();
      case 'I': return this.demangleDependentProtocolConformanceInherited();
      case 'P':
        return this.createWithChild(
            K.ProtocolConformanceRefInTypeModule, this.popProtocol());
      case 'p':
        return this.createWithChild(
            K.ProtocolConformanceRefInProtocolModule, this.popProtocol());
      case 'X': return this.demanglePackProtocolConformance();

      // Runtime records (type/protocol/conformance/function)
      case 'c':
        return this.createWithChild(K.ProtocolConformanceDescriptorRecord,
                               this.popProtocolConformance());
      case 'n':
        return this.createWithPoppedType(K.NominalTypeDescriptorRecord);
      case 'o': // XXX
        return this.createWithChild(K.OpaqueTypeDescriptorRecord, this.popNode());
      case 'r':
        return this.createWithChild(K.ProtocolDescriptorRecord, this.popProtocol());
      case 'F':
        return this.createNode(K.AccessibleFunctionRecord);

      default:
        this.pushBack();
        this.pushBack();
        return this.demangleIdentifier();
      }

    case 'I': return this.demangleImplFunctionType();
    case 'K': return this.createNode(K.ThrowsAnnotation);
    case 'L': return this.demangleLocalIdentifier();
    case 'M': return this.demangleMetatype();
    case 'N': return this.createWithChild(K.TypeMetadata,
                                     this.popNode(K.Type));
    case 'O': return this.demangleAnyGenericType(K.Enum);
    case 'P': return this.demangleAnyGenericType(K.Protocol);
    case 'Q': return this.demangleArchetype();
    case 'R': return this.demangleGenericRequirement();
    case 'S': return this.demangleStandardSubstitution();
    case 'T': return this.demangleThunkOrSpecialization();
    case 'V': return this.demangleAnyGenericType(K.Structure);
    case 'W': return this.demangleWitness();
    case 'X': return this.demangleSpecialType();
    case 'Y': return this.demangleTypeAnnotation();
    case 'Z': return this.createWithChild(K.Static, this.popNode(this.isEntity));
    case 'a': return this.demangleAnyGenericType(K.TypeAlias);
    case 'c': return this.popFunctionType(K.FunctionType);
    case 'd': return this.createNode(K.VariadicMarker);
    case 'f': return this.demangleFunctionEntity();
    case 'g': return this.demangleRetroactiveConformance();
    case 'h': return this.createType(this.createWithChild(K.Shared,
                                                this.popTypeAndGetChild()));
    case 'i': return this.demangleSubscript();
    case 'l': return this.demangleGenericSignature(/*hasParamCounts*/ false);
    case 'm': return this.createType(this.createWithChild(K.Metatype,
                                                this.popNode(K.Type)));
    case 'n':
      return this.createType(
          this.createWithChild(K.Owned, this.popTypeAndGetChild()));
    case 'o': return this.demangleOperatorIdentifier();
    case 'p': return this.demangleProtocolListType();
    case 'q': return this.createType(this.demangleGenericParamIndex());
    case 'r': return this.demangleGenericSignature(/*hasParamCounts*/ true);
    case 's': return this.createNode(K.Module, STDLIB_NAME);
    case 't': return this.popTuple();
    case 'u': return this.demangleGenericType();
    case 'v': return this.demangleVariable();
    case 'w': return this.demangleValueWitness();
    case 'x': return this.createType(this.getDependentGenericParamType(0, 0));
    case 'y': return this.createNode(K.EmptyList);
    case 'z': return this.createType(this.createWithChild(K.InOut,
                                                this.popTypeAndGetChild()));
    case '_': return this.createNode(K.FirstElementMarker);
    case '.':
      // IRGen still uses '.<n>' to disambiguate partial apply thunks and
      // outlined copy functions. We treat such a suffix as "unmangled suffix".
      this.pushBack();
      return this.createNode(K.Suffix, this.consumeAll());
    default:
      this.pushBack();
      return this.demangleIdentifier();
  }
}

  demangleNatural(): number {
  if (!isDigit(this.peekChar()))
    return -1000;
  let num = 0;
  while (true) {
    let c = this.peekChar();
    if (!isDigit(c))
      return num;
    let newNum = (10 * num) + (charCode(c) - 48);
    if (newNum < num || newNum > 0x7fffffff)
      return -1000;
    num = newNum;
    this.nextChar();
  }
}

  demangleIndex(): number {
  if (this.nextIf('_'))
    return 0;
  let num = this.demangleNatural();
  if (num >= 0 && this.nextIf('_'))
    return num + 1;
  return -1000;
}

  demangleIndexAsNode(): Node {
  let Idx = this.demangleIndex();
  if (Idx >= 0)
    return this.createNode(K.Number, Idx);
  return NONE;
}

  demangleMultiSubstitutions(): Node {
  let RepeatCount = -1;
  while (true) {
    let c = this.nextChar();
    if (c == '\0') {
      // End of text.
      return NONE;
    }
    if (isLowerLetter(c)) {
      // It's a substitution with an index < 26.
      let Nd = this.pushMultiSubstitutions(RepeatCount, charCode(c) - 97);
      if (!Nd)
        return NONE;
      this.pushNode(Nd);
      RepeatCount = -1;
      // A lowercase letter indicates that there are more substitutions to
      // follow.
      continue;
    }
    if (isUpperLetter(c)) {
      // The last substitution.
      return this.pushMultiSubstitutions(RepeatCount, charCode(c) - 65);
    }
    if (c == '_') {
      // The previously demangled number is actually not a repeat count but
      // the large (> 26) index of a substitution. Because it's an index we
      // have to add 27 and not 26.
      let Idx = RepeatCount + 27;
      if (Idx >= this.Substitutions.length)
        return NONE;
      return this.Substitutions[Idx]!;
    }
    this.pushBack();
    // Not a letter? Then it can only be a natural number which might be the
    // repeat count or a large (> 26) substitution index.
    RepeatCount = this.demangleNatural();
    if (RepeatCount < 0)
      return NONE;
  }
}

  pushMultiSubstitutions(RepeatCount: number, SubstIdx: number): Node {
  if (SubstIdx >= this.Substitutions.length)
    return NONE;
  if (RepeatCount > 2048)
    return NONE;
  let Nd = this.Substitutions[SubstIdx]!;
  while (RepeatCount-- > 1) {
    this.pushNode(Nd);
  }
  return Nd;
}

  createSwiftType(typeKind: Kind, name: string): Node {
  return this.createType(this.createWithChildren(typeKind,
    this.createNode(K.Module, STDLIB_NAME),
    this.createNode(K.Identifier, name)));
}

  demangleStandardSubstitution(): Node {
  const c = this.nextChar(); switch (c) {
    case 'o':
      return this.createNode(K.Module, MANGLING_MODULE_OBJC);
    case 'C':
      return this.createNode(K.Module, MANGLING_MODULE_CLANG_IMPORTER);
    case 'g': {
      let OptionalTy =
        this.createType(this.createWithChildren(K.BoundGenericEnum,
          this.createSwiftType(K.Enum, "Optional"),
          this.createWithChild(K.TypeList, this.popNode(K.Type))));
      this.addSubstitution(OptionalTy);
      return OptionalTy;
    }
    default: {
      this.pushBack();
      let RepeatCount = this.demangleNatural();
      if (RepeatCount > 2048)

        return NONE;
      let secondLevelSubstitution = this.nextIf('c');
      const Nd = this.createStandardSubstitution(
              this.nextChar(), secondLevelSubstitution);
      if (Nd) {
        while (RepeatCount-- > 1) {
          this.pushNode(Nd);
        }
        return Nd;
      }
      return NONE;
    }
  }
}

  createStandardSubstitution(Subst: string, SecondLevel: boolean): Node {
  const e = (SecondLevel ? N.STANDARD_TYPES_CONCURRENCY : N.STANDARD_TYPES)[Subst];
  if (e && Object.prototype.hasOwnProperty.call(SecondLevel ? N.STANDARD_TYPES_CONCURRENCY : N.STANDARD_TYPES, Subst))
    return this.createSwiftType(e[0], e[1]);
  return NONE;
}

  demangleIdentifier(): Node {
  let hasWordSubsts = false;
  let isPunycoded = false;
  let c = this.peekChar();
  if (!isDigit(c))
    return NONE;
  if (c == '0') {
    this.nextChar();
    if (this.peekChar() == '0') {
      this.nextChar();
      isPunycoded = true;
    } else {
      hasWordSubsts = true;
    }
  }
  let Identifier = '';
  do {
    while (hasWordSubsts && isLetter(this.peekChar())) {
      let c = this.nextChar();
      let WordIdx = 0;
      if (isLowerLetter(c)) {
        WordIdx = charCode(c) - 97;
      } else {
        WordIdx = charCode(c) - 65;
        hasWordSubsts = false;
      }
      if (WordIdx >= this.NumWords)
        return NONE;
      /* assert */ void 0;
      let Slice = this.Words[WordIdx]!;
      Identifier += Slice;
    }
    if (this.nextIf('0'))
      break;
    let numChars = this.demangleNatural();
    if (numChars <= 0)
      return NONE;
    if (isPunycoded)
      this.nextIf('_');
    if (this.Pos + numChars > this.Text.length)
      return NONE;
    let Slice = this.Text.substr(this.Pos, numChars);
    if (isPunycoded) {
      const PunycodedString = decodePunycodeString(Slice);
      if (PunycodedString === undefined)
        return NONE;
      Identifier += PunycodedString;
    } else {
      Identifier += Slice;
      let wordStartPos = -1;
      for (let Idx = 0, End = Slice.length; Idx <= End; ++Idx) {
        let c = (Idx < End ? Slice[Idx]! : '\0');
        if (wordStartPos >= 0 && isWordEnd(c, Slice[Idx - 1] ?? '\0')) {
          if (Idx - wordStartPos >= 2 && this.NumWords < Demangler.MaxNumWords) {
            let word = Slice.substr(wordStartPos, Idx - wordStartPos);
            this.Words[this.NumWords++] = word;
          }
          wordStartPos = -1;
        }
        if (wordStartPos < 0 && isWordStart(c)) {
          wordStartPos = Idx;
        }
      }
    }
    this.Pos += numChars;
  } while (hasWordSubsts);

  if (Identifier.length === 0)
    return NONE;
  let Ident = this.createNode(K.Identifier, Identifier);
  this.addSubstitution(Ident);
  return Ident;
}

  demangleOperatorIdentifier(): Node {
  let Ident = this.popNode(K.Identifier);
  if (!Ident)
    return NONE;

  const op_char_table = "& @/= >    <*!|+?%-~   ^ .";

  let OpStr = '';
  for (const c of Ident.getText()) {
    if (charCode(c) >= 0x80) {
      // Pass through Unicode characters.
      OpStr += c;
      continue;
    }
    if (!isLowerLetter(c))
      return NONE;
    let o = op_char_table[charCode(c) - 97]!;
    if (o == ' ')
      return NONE;
    OpStr += o;
  }
  switch (this.nextChar()) {
    case 'i': return this.createNode(K.InfixOperator, OpStr);
    case 'p': return this.createNode(K.PrefixOperator, OpStr);
    case 'P': return this.createNode(K.PostfixOperator, OpStr);
    default: return NONE;
  }
}

  demangleLocalIdentifier(): Node {
  if (this.nextIf('L')) {
    let discriminator = this.popNode(K.Identifier);
    let name = this.popNode(this.isDeclName);
    return this.createWithChildren(K.PrivateDeclName, discriminator, name);
  }
  if (this.nextIf('l')) {
    let discriminator = this.popNode(K.Identifier);
    return this.createWithChild(K.PrivateDeclName, discriminator);
  }
  if ((this.peekChar() >= 'a' && this.peekChar() <= 'j') ||
      (this.peekChar() >= 'A' && this.peekChar() <= 'J')) {
    let relatedEntityKind = this.nextChar();
    let kindNd = this.createNode(K.Identifier, relatedEntityKind);
    let name = this.popNode();
    let result = this.createNode(K.RelatedEntityDeclName);
    this.addChild(result, kindNd);
    return this.addChild(result, name);
  }
  let discriminator = this.demangleIndexAsNode();
  let name = this.popNode(this.isDeclName);
  return this.createWithChildren(K.LocalDeclName, discriminator, name);
}

  popModule(): Node {
  const Ident = this.popNode(K.Identifier);
  if (Ident)
    return this.changeKind(Ident, K.Module);
  return this.popNode(K.Module);
}

  popContext(): Node {
  const Mod = this.popModule();
  if (Mod)
    return Mod;

  const Ty = this.popNode(K.Type);
  if (Ty) {
    if (Ty.getNumChildren() != 1)
      return NONE;
    let Child = Ty.getFirstChild();
    if (!isContext(Child.getKind()))
      return NONE;
    return Child;
  }
  return this.popNode(isContext);
}

  popTypeAndGetChild(): Node {
  let Ty = this.popNode(K.Type);
  if (!Ty || Ty.getNumChildren() != 1)
    return NONE;
  return Ty.getFirstChild();
}

  popTypeAndGetAnyGeneric(): Node {
  let Child = this.popTypeAndGetChild();
  if (Child && this.isAnyGeneric(Child.getKind()))
    return Child;
  return NONE;
}

  demangleBuiltinType(): Node {
  let Ty: Node;
  let maxTypeSize = 4096; // a very conservative upper bound
  switch (this.nextChar()) {
    case 'b':
      Ty = this.createNode(K.BuiltinTypeName,
                               N.BUILTIN_TYPE_NAME_BRIDGEOBJECT);
      break;
    case 'B':
      Ty = this.createNode(K.BuiltinTypeName,
                              N.BUILTIN_TYPE_NAME_UNSAFEVALUEBUFFER);
      break;
    case 'e':
      Ty = this.createNode(K.BuiltinTypeName,
                              N.BUILTIN_TYPE_NAME_EXECUTOR);
      break;
    case 'f': {
      let size = this.demangleIndex() - 1;
      if (size <= 0 || size > maxTypeSize)
        return NONE;
      let name = N.BUILTIN_TYPE_NAME_FLOAT + size;
      Ty = this.createNode(K.BuiltinTypeName, name);
      break;
    }
    case 'i': {
      let size = this.demangleIndex() - 1;
      if (size <= 0 || size > maxTypeSize)
        return NONE;
      let name = N.BUILTIN_TYPE_NAME_INT + size;
      Ty = this.createNode(K.BuiltinTypeName, name);
      break;
    }
    case 'I':
      Ty = this.createNode(K.BuiltinTypeName,
                      N.BUILTIN_TYPE_NAME_INTLITERAL);
      break;
    case 'v': {
      let elts = this.demangleIndex() - 1;
      if (elts <= 0 || elts > maxTypeSize)
        return NONE;
      let EltType = this.popTypeAndGetChild();
      if (!EltType || EltType.getKind() != K.BuiltinTypeName ||
          !EltType.getText().startsWith(N.BUILTIN_TYPE_NAME_PREFIX))
        return NONE;
      let name = N.BUILTIN_TYPE_NAME_VEC + elts + 'x' + EltType.getText().substr(N.BUILTIN_TYPE_NAME_PREFIX.length);
      Ty = this.createNode(K.BuiltinTypeName, name);
      break;
    }
    case 'O':
      Ty = this.createNode(K.BuiltinTypeName,
                               N.BUILTIN_TYPE_NAME_UNKNOWNOBJECT);
      break;
    case 'o':
      Ty = this.createNode(K.BuiltinTypeName,
                               N.BUILTIN_TYPE_NAME_NATIVEOBJECT);
      break;
    case 'p':
      Ty = this.createNode(K.BuiltinTypeName,
                               N.BUILTIN_TYPE_NAME_RAWPOINTER);
      break;
    case 'j':
      Ty = this.createNode(K.BuiltinTypeName,
                               N.BUILTIN_TYPE_NAME_JOB);
      break;
    case 'D':
      Ty = this.createNode(K.BuiltinTypeName,
                               N.BUILTIN_TYPE_NAME_DEFAULTACTORSTORAGE);
      break;
    case 'd':
      Ty = this.createNode(K.BuiltinTypeName,
                               N.BUILTIN_TYPE_NAME_NONDEFAULTDISTRIBUTEDACTORSTORAGE);
      break;
    case 'c':
      Ty = this.createNode(K.BuiltinTypeName,
                               N.BUILTIN_TYPE_NAME_RAWUNSAFECONTINUATION);
      break;
    case 't':
      Ty = this.createNode(K.BuiltinTypeName, N.BUILTIN_TYPE_NAME_SILTOKEN);
      break;
    case 'w':
      Ty = this.createNode(K.BuiltinTypeName,
                               N.BUILTIN_TYPE_NAME_WORD);
      break;
    case 'P':
      Ty = this.createNode(K.BuiltinTypeName,
                               N.BUILTIN_TYPE_NAME_PACKINDEX);
      break;
    case 'T':
      Ty = this.createNode(K.BuiltinTupleType);
      break;
    default:
      return NONE;
  }
  return this.createType(Ty);
}

  demangleAnyGenericType(kind: Kind): Node {
  let Name = this.popNode(this.isDeclName);
  let Ctx = this.popContext();
  let NTy = this.createType(this.createWithChildren(kind, Ctx, Name));
  this.addSubstitution(NTy);
  return NTy;
}

  demangleExtensionContext(): Node {
  let GenSig = this.popNode(K.DependentGenericSignature);
  let Module = this.popModule();
  let Type = this.popTypeAndGetAnyGeneric();
  let Ext = this.createWithChildren(K.Extension, Module, Type);
  if (GenSig)
    Ext = this.addChild(Ext, GenSig);
  return Ext;
}


  setParentForOpaqueReturnTypeNodes(D: Demangler, parent: Node, visitedNode: Node): Node {
  if (!parent || !visitedNode)
    return NONE;
  if (visitedNode.getKind() == K.OpaqueReturnType) {
    // If this node is not already parented, parent it.
    if (visitedNode.hasChildren()
        && visitedNode.getLastChild().getKind() == K.OpaqueReturnTypeParent) {
      return parent;
    }
    // The C++ stores the parent pointer as the node's index; only identity matters here.
    const marker = D.createNode(K.OpaqueReturnTypeParent);
    (marker as Node & { parentRef?: Node }).parentRef = parent;
    visitedNode.addChild(marker);
    return parent;
  }
  
  // If this node is one that may in turn define its own opaque return type,
  // stop recursion, since any opaque return type nodes underneath would refer
  // to the nested declaration rather than the one we're looking at.
  if (visitedNode.getKind() == K.Function
      || visitedNode.getKind() == K.Variable
      || visitedNode.getKind() == K.Subscript) {
    return parent;
  }
  
  for (let i = 0, e = visitedNode.getNumChildren(); i < e; ++i) {
    this.setParentForOpaqueReturnTypeNodes(D, parent, visitedNode.getChild(i));
  }
  return parent;
}

  demanglePlainFunction(): Node {
  let GenSig = this.popNode(K.DependentGenericSignature);
  let Type = this.popFunctionType(K.FunctionType);
  let LabelList = this.popFunctionParamLabels(Type);

  if (GenSig) {
    Type = this.createType(this.createWithChildren(K.DependentGenericType,
                                         GenSig, Type));
  }

  let Name = this.popNode(this.isDeclName);
  let Ctx = this.popContext();

  let result = LabelList
    ? this.createWithChildren(K.Function, Ctx, Name, LabelList, Type)
    : this.createWithChildren(K.Function, Ctx, Name, Type);
    
  result = this.setParentForOpaqueReturnTypeNodes(this, result, Type);
  return result;
}

  popFunctionType(kind: Kind, hasClangType: boolean = false): Node {
  let FuncType = this.createNode(kind);
  let ClangType = NONE;
  if (hasClangType) {
    ClangType = this.demangleClangType();
  }
  this.addChild(FuncType, ClangType);
  this.addChild(FuncType, this.popNode(K.SelfLifetimeDependence));
  this.addChild(FuncType, this.popNode(K.GlobalActorFunctionType));
  this.addChild(FuncType, this.popNode(K.IsolatedAnyFunctionType));
  this.addChild(FuncType, this.popNode(K.SendingResultFunctionType));
  this.addChild(FuncType, this.popNode(K.DifferentiableFunctionType));
  this.addChild(FuncType, this.popNode((kind: Kind) => {
    return kind == K.ThrowsAnnotation ||
      kind == K.TypedThrowsAnnotation;
  }));
  this.addChild(FuncType, this.popNode(K.ConcurrentFunctionType));
  this.addChild(FuncType, this.popNode(K.AsyncAnnotation));

  FuncType = this.addChild(FuncType, this.popFunctionParams(K.ArgumentTuple));
  FuncType = this.addChild(FuncType, this.popFunctionParams(K.ReturnType));
  return this.createType(FuncType);
}

  popFunctionParams(kind: Kind): Node {
  let ParamsType: Node;
  if (this.popNode(K.EmptyList)) {
    ParamsType = this.createType(this.createNode(K.Tuple));
  } else {
    ParamsType = this.popNode(K.Type);
  }
  return this.createWithChild(kind, ParamsType);
}

  popFunctionParamLabels(Type: Node): Node {
  if (!this.IsOldFunctionTypeMangling && this.popNode(K.EmptyList))
    return this.createNode(K.LabelList);

  if (!Type || Type.getKind() != K.Type)
    return NONE;

  let FuncType = Type.getFirstChild();
  if (FuncType.getKind() == K.DependentGenericType)
    FuncType = FuncType.getChild(1).getFirstChild();

  if (FuncType.getKind() != K.FunctionType &&
      FuncType.getKind() != K.NoEscapeFunctionType)
    return NONE;

  let FirstChildIdx = 0;
  if (FuncType.getChild(FirstChildIdx).getKind() ==
      K.SelfLifetimeDependence)
    ++FirstChildIdx;
  if (FuncType.getChild(FirstChildIdx).getKind()
        == K.GlobalActorFunctionType)
    ++FirstChildIdx;
  if (FuncType.getChild(FirstChildIdx).getKind()
        == K.IsolatedAnyFunctionType)
    ++FirstChildIdx;
  if (FuncType.getChild(FirstChildIdx).getKind() ==
      K.SendingResultFunctionType)
    ++FirstChildIdx;
  if (FuncType.getChild(FirstChildIdx).getKind()
        == K.DifferentiableFunctionType)
    ++FirstChildIdx;
  if (FuncType.getChild(FirstChildIdx).getKind()
        == K.ThrowsAnnotation ||
      FuncType.getChild(FirstChildIdx).getKind()
        == K.TypedThrowsAnnotation)
    ++FirstChildIdx;
  if (FuncType.getChild(FirstChildIdx).getKind()
        == K.ConcurrentFunctionType)
    ++FirstChildIdx;
  if (FuncType.getChild(FirstChildIdx).getKind()
        == K.AsyncAnnotation)
    ++FirstChildIdx;
  if (FuncType.getChild(FirstChildIdx).getKind() ==
      K.ParamLifetimeDependence)
    ++FirstChildIdx;
  let ParameterType = FuncType.getChild(FirstChildIdx);

  /* assert */ void 0;

  let ParamsType = ParameterType.getFirstChild();
  /* assert */ void 0;
  let Params = ParamsType.getFirstChild();
  let NumParams =
    Params.getKind() == K.Tuple ? Params.getNumChildren() : 1;

  if (NumParams == 0)
    return NONE;

  let getChildIf = (Node: Node, filterBy: Kind): [Node, number] => {
    for (let i = 0, n = Node.getNumChildren(); i != n; ++i) {
      let Child = Node.getChild(i);
      if (Child.getKind() == filterBy)
        return [Child, i];
    }
    return [NONE, 0];
  };

  let getLabel = (Params: Node, Idx: number): Node => {
    // Old-style function type mangling has labels as part of the argument.
    if (this.IsOldFunctionTypeMangling) {
      let Param = Params.getChild(Idx);
      let Label = getChildIf(Param, K.TupleElementName);

      if (Label[0]) {
        Param.removeChildAt(Label[1]);
        return this.createNodeWithAllocatedText(K.Identifier,
                                           Label[0].getText());
      }

      return this.createNode(K.FirstElementMarker);
    }

    return this.popNode();
  };

  let LabelList = this.createNode(K.LabelList);
  let Tuple = ParameterType.getFirstChild().getFirstChild();

  if (this.IsOldFunctionTypeMangling &&
      (!Tuple || Tuple.getKind() != K.Tuple))
    return LabelList;

  let hasLabels = false;
  for (let i = 0; i != NumParams; ++i) {
    let Label = getLabel(Tuple, i);

    if (!Label)
      return NONE;

    if (Label.getKind() != K.Identifier &&
        Label.getKind() != K.FirstElementMarker)
      return NONE;

    LabelList.addChild(Label);
    hasLabels = hasLabels || Label.getKind() != K.FirstElementMarker;
  }

  // Old style label mangling can produce label list without
  // actual labels, we need to support that case specifically.
  if (!hasLabels)
    return this.createNode(K.LabelList);

  if (!this.IsOldFunctionTypeMangling)
    LabelList.reverseChildren();

  return LabelList;
}

  popTuple(): Node {
  let Root = this.createNode(K.Tuple);

  if (!this.popNode(K.EmptyList)) {
    let firstElem = false;
    do {
      firstElem = (this.popNode(K.FirstElementMarker) != NONE);
      let TupleElmt = this.createNode(K.TupleElement);
      this.addChild(TupleElmt, this.popNode(K.VariadicMarker));
      const Ident = this.popNode(K.Identifier);
      if (Ident) {
        TupleElmt.addChild(this.createNodeWithAllocatedText(
                              K.TupleElementName, Ident.getText()));
      }
      let Ty = this.popNode(K.Type);
      if (!Ty)
        return NONE;
      TupleElmt.addChild(Ty);
      Root.addChild(TupleElmt);
    } while (!firstElem);

    Root.reverseChildren();
  }
  return this.createType(Root);
}

  popPack(): Node {
  let Root = this.createNode(K.Pack);

  if (!this.popNode(K.EmptyList)) {
    let firstElem = false;
    do {
      firstElem = (this.popNode(K.FirstElementMarker) != NONE);
      let Ty = this.popNode(K.Type);
      if (!Ty)
        return NONE;
      Root.addChild(Ty);
    } while (!firstElem);

    Root.reverseChildren();
  }
  return this.createType(Root);
}

  popSILPack(): Node {
  let Root: Node;


  switch (this.nextChar()) {
  case 'd':
    Root = this.createNode(K.SILPackDirect);
    break;

  case 'i':
    Root = this.createNode(K.SILPackIndirect);
    break;

  default:
    return NONE;
  }

  if (!this.popNode(K.EmptyList)) {
    let firstElem = false;
    do {
      firstElem = (this.popNode(K.FirstElementMarker) != NONE);
      let Ty = this.popNode(K.Type);
      if (!Ty)
        return NONE;
      Root.addChild(Ty);
    } while (!firstElem);

    Root.reverseChildren();
  }

  return this.createType(Root);
}

  popTypeList(): Node {
  let Root = this.createNode(K.TypeList);

  if (!this.popNode(K.EmptyList)) {
    let firstElem = false;
    do {
      firstElem = (this.popNode(K.FirstElementMarker) != NONE);
      let Ty = this.popNode(K.Type);
      if (!Ty)
        return NONE;
      Root.addChild(Ty);
    } while (!firstElem);
    
    Root.reverseChildren();
  }
  return Root;
}

  popProtocol(): Node {
  const Type = this.popNode(K.Type);
  if (Type) {
    if (Type.getNumChildren() < 1)
      return NONE;

    if (!this.isProtocolNode(Type))
      return NONE;

    return Type;
  }
  
  const SymbolicRef = this.popNode(K.ProtocolSymbolicReference);
  if (SymbolicRef){
    return SymbolicRef;
  }
  const SymbolicRef2 = this.popNode(K.ObjectiveCProtocolSymbolicReference);
  if (SymbolicRef2) {
    return SymbolicRef2;
  }

  let Name = this.popNode(this.isDeclName);
  let Ctx = this.popContext();
  let Proto = this.createWithChildren(K.Protocol, Ctx, Name);
  return this.createType(Proto);
}

  popAnyProtocolConformanceList(): Node {
  let conformanceList = this.createNode(K.AnyProtocolConformanceList);
  if (!this.popNode(K.EmptyList)) {
    let firstElem = false;
    do {
      firstElem = (this.popNode(K.FirstElementMarker) != NONE);
      let anyConformance = this.popAnyProtocolConformance();
      if (!anyConformance)
        return NONE;
      conformanceList.addChild(anyConformance);
    } while (!firstElem);

    conformanceList.reverseChildren();
  }
  return conformanceList;
}

  popAnyProtocolConformance(): Node {
  return this.popNode((kind: Kind) => {
    switch (kind) {
    case K.ConcreteProtocolConformance:
    case K.PackProtocolConformance:
    case K.DependentProtocolConformanceRoot:
    case K.DependentProtocolConformanceInherited:
    case K.DependentProtocolConformanceAssociated:
      return true;

    default:
      return false;
    }
  });
}

  demangleRetroactiveProtocolConformanceRef(): Node {
  let module = this.popModule();
  let proto = this.popProtocol();
  let protocolConformanceRef =
      this.createWithChildren(K.ProtocolConformanceRefInOtherModule,
                         proto, module);
  return protocolConformanceRef;
}

  demangleConcreteProtocolConformance(): Node {
  let conditionalConformanceList = this.popAnyProtocolConformanceList();

  let conformanceRef =
      this.popNode(K.ProtocolConformanceRefInTypeModule);
  if (!conformanceRef) {
    conformanceRef =
        this.popNode(K.ProtocolConformanceRefInProtocolModule);
  }
  if (!conformanceRef)
    conformanceRef = this.demangleRetroactiveProtocolConformanceRef();

  let type = this.popNode(K.Type);
  return this.createWithChildren(K.ConcreteProtocolConformance,
                            type, conformanceRef, conditionalConformanceList);
}

  demanglePackProtocolConformance(): Node {
  let patternConformanceList = this.popAnyProtocolConformanceList();

  return this.createWithChild(K.PackProtocolConformance,
                         patternConformanceList);
}

  popDependentProtocolConformance(): Node {
  return this.popNode((kind: Kind) => {
    switch (kind) {
    case K.DependentProtocolConformanceRoot:
    case K.DependentProtocolConformanceInherited:
    case K.DependentProtocolConformanceAssociated:
      return true;

    default:
      return false;
    }
  });
}

  demangleDependentProtocolConformanceRoot(): Node {
  let index = this.demangleDependentConformanceIndex();
  let protocol = this.popProtocol();
  let dependentType = this.popNode(K.Type);
  return this.createWithChildren(K.DependentProtocolConformanceRoot,
                            dependentType, protocol, index);
}

  demangleDependentProtocolConformanceInherited(): Node {
  let index = this.demangleDependentConformanceIndex();
  let protocol = this.popProtocol();
  let nested = this.popDependentProtocolConformance();
  return this.createWithChildren(K.DependentProtocolConformanceInherited,
                            nested, protocol, index);
}

  popDependentAssociatedConformance(): Node {
  let protocol = this.popProtocol();
  let dependentType = this.popNode(K.Type);
  return this.createWithChildren(K.DependentAssociatedConformance,
                            dependentType, protocol);
}

  demangleDependentProtocolConformanceAssociated(): Node {
  let index = this.demangleDependentConformanceIndex();
  let associatedConformance = this.popDependentAssociatedConformance();
  let nested = this.popDependentProtocolConformance();
  return this.createWithChildren(K.DependentProtocolConformanceAssociated,
                            nested, associatedConformance, index);
}

  demangleDependentConformanceIndex(): Node {
  let index = this.demangleIndex();
  // index < 0 indicates a demangling error.
  // index == 0 is ill-formed by the (originally buggy) use of this production.
  if (index <= 0) return NONE;

  // index == 1 indicates an unknown index.
  if (index == 1) return this.createNode(K.UnknownIndex);

  // Remove the index adjustment.
  return this.createNode(K.Index, index - 2);
}

  demangleRetroactiveConformance(): Node {
  let index = this.demangleIndexAsNode();
  let conformance = this.popAnyProtocolConformance();
  return this.createWithChildren(K.RetroactiveConformance, index, conformance);
}

  popRetroactiveConformances(): Node {
  let conformancesNode = NONE;
  for (let conformance = this.popNode(K.RetroactiveConformance); conformance; conformance = this.popNode(K.RetroactiveConformance)) {
    if (!conformancesNode)
      conformancesNode = this.createNode(K.TypeList);
    conformancesNode.addChild(conformance);
  }
  if (conformancesNode)
    conformancesNode.reverseChildren();
  return conformancesNode;
}

  demangleBoundGenerics(TypeListList: Node[], Retro: { v: Node }): boolean {
  Retro.v = this.popRetroactiveConformances();
  
  for (;;) {
    let TList = this.createNode(K.TypeList);
    TypeListList.push(TList);
    for (let Ty = this.popNode(K.Type); Ty; Ty = this.popNode(K.Type)) {
      TList.addChild(Ty);
    }
    TList.reverseChildren();
    
    if (this.popNode(K.EmptyList))
      break;
    if (!this.popNode(K.FirstElementMarker))
      return false;
  }
  return true;
}

  demangleBoundGenericType(): Node {
  let Retro = { v: NONE };
  let TypeListList: Node[] = [];
  if (!this.demangleBoundGenerics(TypeListList, Retro))
    return NONE;
  let RetroactiveConformances = Retro.v;

  let Nominal = this.popTypeAndGetAnyGeneric();
  if (!Nominal)
    return NONE;
  let BoundNode = this.demangleBoundGenericArgs(Nominal, TypeListList, 0);
  if (!BoundNode)
    return NONE;
  this.addChild(BoundNode, RetroactiveConformances);
  let NTy = this.createType(BoundNode);
  this.addSubstitution(NTy);
  return NTy;
}

  nodeConsumesGenericArgs(node: Node): boolean {
  switch (node.getKind()) {
    case K.Variable:
    case K.Subscript:
    case K.ImplicitClosure:
    case K.ExplicitClosure:
    case K.DefaultArgumentInitializer:
    case K.Initializer:
    case K.PropertyWrapperBackingInitializer:
    case K.PropertyWrapperInitFromProjectedValue:
    case K.Static:
      return false;
    default:
      return true;
  }
}

  demangleBoundGenericArgs(Nominal: Node, TypeLists: Node[], TypeListIdx: number): Node {
  // TODO: This would be a lot easier if we represented bound generic args
  // flatly in the demangling tree, since that's how they're mangled and also
  // how the runtime generally wants to consume them.
  
  if (!Nominal)
    return NONE;

  if (TypeListIdx >= TypeLists.length)
    return NONE;

  // Associate a context symbolic reference with all remaining generic
  // arguments.
  if (Nominal.getKind() == K.TypeSymbolicReference
      || Nominal.getKind() == K.ProtocolSymbolicReference) {
    let remainingTypeList = this.createNode(K.TypeList);
    for (let i = TypeLists.length - 1;
         i >= TypeListIdx && i < TypeLists.length;
         --i) {
      let list = TypeLists[i]!;
      for (const child of list.children) {
        remainingTypeList.addChild(child);
      }
    }
    return this.createWithChildren(K.BoundGenericOtherNominalType,
                              this.createType(Nominal), remainingTypeList);
  }

  // Generic arguments for the outermost type come first.
  if (Nominal.getNumChildren() == 0)
    return NONE;
  let Context = Nominal.getFirstChild();

  let consumesGenericArgs = this.nodeConsumesGenericArgs(Nominal);

  let args = TypeLists[TypeListIdx]!;

  if (consumesGenericArgs)
    ++TypeListIdx;

  if (TypeListIdx < TypeLists.length) {
    let BoundParent: Node;
    if (Context.getKind() == K.Extension) {
      BoundParent = this.demangleBoundGenericArgs(Context.getChild(1), TypeLists,
                                             TypeListIdx);
      BoundParent = this.createWithChildren(K.Extension,
                                       Context.getFirstChild(),
                                       BoundParent);
      if (Context.getNumChildren() == 3) {
        // Add the generic signature of the extension context.
        this.addChild(BoundParent, Context.getChild(2));
      }
    } else {
      BoundParent = this.demangleBoundGenericArgs(Context, TypeLists, TypeListIdx);
    }
    // Rebuild this type with the new parent type, which may have
    // had its generic arguments applied.
    let NewNominal = this.createWithChild(Nominal.getKind(), BoundParent);
    if (!NewNominal)
      return NONE;

    // Append remaining children of the origin nominal.
    for (let Idx = 1; Idx < Nominal.getNumChildren(); ++Idx) {
      this.addChild(NewNominal, Nominal.getChild(Idx));
    }
    Nominal = NewNominal;
  }
  if (!consumesGenericArgs)
    return Nominal;

  // If there were no arguments at this level there is nothing left
  // to do.
  if (args.getNumChildren() == 0)
    return Nominal;

  let kind: Kind;
  switch (Nominal.getKind()) {
  case K.Class:
    kind = K.BoundGenericClass;
    break;
  case K.Structure:
    kind = K.BoundGenericStructure;
    break;
  case K.Enum:
    kind = K.BoundGenericEnum;
    break;
  case K.Protocol:
    kind = K.BoundGenericProtocol;
    break;
  case K.OtherNominalType:
    kind = K.BoundGenericOtherNominalType;
    break;
  case K.TypeAlias:
    kind = K.BoundGenericTypeAlias;
    break;
  case K.Function:
  case K.Constructor:
    // Well, not really a nominal type.
    return this.createWithChildren(K.BoundGenericFunction, Nominal, args);
  default:
    return NONE;
  }
  return this.createWithChildren(kind, this.createType(Nominal), args);
}

  demangleImplParamConvention(ConvKind: Kind): Node {
  let attr = '';
  switch (this.nextChar()) {
    case 'i': attr = "@in"; break;
    case 'c':
      attr = "@in_constant";
      break;
    case 'l': attr = "@inout"; break;
    case 'b': attr = "@inout_aliasable"; break;
    case 'n': attr = "@in_guaranteed"; break;
    case 'x': attr = "@owned"; break;
    case 'g': attr = "@guaranteed"; break;
    case 'e': attr = "@deallocating"; break;
    case 'y': attr = "@unowned"; break;
    case 'v': attr = "@pack_owned"; break;
    case 'p': attr = "@pack_guaranteed"; break;
    case 'm': attr = "@pack_inout"; break;
    default:
      this.pushBack();
      return NONE;
  }
  return this.createWithChild(ConvKind,
                         this.createNode(K.ImplConvention, attr));
}

  demangleImplResultConvention(ConvKind: Kind): Node {
  let attr = '';
  switch (this.nextChar()) {
    case 'r': attr = "@out"; break;
    case 'o': attr = "@owned"; break;
    case 'd': attr = "@unowned"; break;
    case 'u': attr = "@unowned_inner_pointer"; break;
    case 'a': attr = "@autoreleased"; break;
    case 'k': attr = "@pack_out"; break;
    default:
      this.pushBack();
      return NONE;
  }
  return this.createWithChild(ConvKind,
                         this.createNode(K.ImplConvention, attr));
}

  demangleImplParameterSending(): Node {
  // Empty string represents default differentiability.
  if (!this.nextIf('T'))
    return NONE;
  let attr = "sending";
  return this.createNode(K.ImplParameterSending, attr);
}

  demangleImplParameterResultDifferentiability(): Node {
  // Empty string represents default differentiability.
  let attr = "";
  if (this.nextIf('w'))
    attr = "@noDerivative";
  return this.createNode(K.ImplParameterResultDifferentiability, attr);
}

  demangleClangType(): Node {
  let numChars = this.demangleNatural();
  if (numChars <= 0 || this.Pos + numChars > this.Text.length)
    return NONE;
  let mangledClangType = this.Text.substr(this.Pos, numChars);
  this.Pos = this.Pos + numChars;
  return this.createNode(K.ClangType, mangledClangType);
}

  demangleImplFunctionType(): Node {
  let type = this.createNode(K.ImplFunctionType);

  if (this.nextIf('s')) {
    let Substitutions: Node[] = [];
    let Retro = { v: NONE };
    if (!this.demangleBoundGenerics(Substitutions, Retro))
      return NONE;
    let SubstitutionRetroConformances = Retro.v;

    let sig = this.popNode(K.DependentGenericSignature);
    if (!sig)
      return NONE;

    let subsNode = this.createNode(K.ImplPatternSubstitutions);
    subsNode.addChild(sig);
    if (Substitutions.length != 1) return NONE;
    subsNode.addChild(Substitutions[0]!);
    if (SubstitutionRetroConformances)
      subsNode.addChild(SubstitutionRetroConformances);
    type.addChild(subsNode);
  }

  if (this.nextIf('I')) {
    let Substitutions: Node[] = [];
    let Retro = { v: NONE };
    if (!this.demangleBoundGenerics(Substitutions, Retro))
      return NONE;
    let SubstitutionRetroConformances = Retro.v;

    let subsNode = this.createNode(K.ImplInvocationSubstitutions);
    if (Substitutions.length != 1)
      return NONE;
    subsNode.addChild(Substitutions[0]!);
    if (SubstitutionRetroConformances)
      subsNode.addChild(SubstitutionRetroConformances);
    type.addChild(subsNode);
  }
  
  let GenSig = this.popNode(K.DependentGenericSignature);
  if (GenSig && this.nextIf('P'))
    GenSig = this.changeKind(GenSig, K.DependentPseudogenericSignature);

  if (this.nextIf('e'))
    type.addChild(this.createNode(K.ImplEscaping));

  if (this.nextIf('A'))
    type.addChild(this.createNode(K.ImplErasedIsolation));

  switch (this.peekChar()) {
  case 'd':
  case 'l':
  case 'f':
  case 'r':

    type.addChild(
        this.createNode(
            K.ImplDifferentiabilityKind, charCode(this.nextChar())));
    break;
  default:
    break;
  }

  let CAttr = '';
  switch (this.nextChar()) {
    case 'y': CAttr = "@callee_unowned"; break;
    case 'g': CAttr = "@callee_guaranteed"; break;
    case 'x': CAttr = "@callee_owned"; break;
    case 't': CAttr = "@convention(thin)"; break;
    default: return NONE;
  }
  type.addChild(this.createNode(K.ImplConvention, CAttr));

  let FConv = '';
  let hasClangType = false;
  switch (this.nextChar()) {
  case 'B': FConv = "block"; break;
  case 'C': FConv = "c"; break;
  case 'z': {
    switch (this.nextChar()) {
    case 'B': hasClangType = true; FConv = "block"; break;
    case 'C': hasClangType = true; FConv = "c"; break;
    default: this.pushBack(); this.pushBack(); break;
    }
    break;
  }
  case 'M': FConv = "method"; break;
  case 'O': FConv = "objc_method"; break;
  case 'K': FConv = "closure"; break;
  case 'W': FConv = "witness_method"; break;
  default: this.pushBack(); break;
  }
  if (FConv) {
    let FAttrNode = this.createNode(K.ImplFunctionConvention);
    FAttrNode.addChild(
        this.createNode(K.ImplFunctionConventionName, FConv));
    if (hasClangType)
      this.addChild(FAttrNode, this.demangleClangType());
    type.addChild(FAttrNode);
  }

  let CoroAttr = '';
  if (this.nextIf('A'))
    CoroAttr = "@yield_once";
  else if (this.nextIf('G'))
    CoroAttr = "@yield_many";
  if (CoroAttr)
    type.addChild(this.createNode(K.ImplFunctionAttribute, CoroAttr));

  if (this.nextIf('h')) {
    type.addChild(this.createNode(K.ImplFunctionAttribute, "@Sendable"));
  }

  if (this.nextIf('H')) {
    type.addChild(this.createNode(K.ImplFunctionAttribute, "@async"));
  }

  this.addChild(type, GenSig);

  let NumTypesToAdd = 0;
  for (let Param = this.demangleImplParamConvention(K.ImplParameter); Param; Param = this.demangleImplParamConvention(K.ImplParameter)) {
    type = this.addChild(type, Param);
    const Diff = this.demangleImplParameterResultDifferentiability();
    if (Diff)
      this.addChild(Param, Diff);
    const Sending = this.demangleImplParameterSending();
    if (Sending)
      this.addChild(Param, Sending);
    ++NumTypesToAdd;
  }

  if (this.nextIf('T')) {
    type.addChild(this.createNode(K.ImplSendingResult));
  }

  for (let Result = this.demangleImplResultConvention(
                                                    K.ImplResult); Result; Result = this.demangleImplResultConvention(
                                                    K.ImplResult)) {
    type = this.addChild(type, Result);
    const Diff = this.demangleImplParameterResultDifferentiability();
    if (Diff)
      this.addChild(Result, Diff);
    ++NumTypesToAdd;
  }
  while (this.nextIf('Y')) {
    let YieldResult =
      this.demangleImplParamConvention(K.ImplYield);
    if (!YieldResult)
      return NONE;
    type = this.addChild(type, YieldResult);
    ++NumTypesToAdd;
  }
  if (this.nextIf('z')) {
    let ErrorResult = this.demangleImplResultConvention(
                                                  K.ImplErrorResult);
    if (!ErrorResult)
      return NONE;
    type = this.addChild(type, ErrorResult);
    ++NumTypesToAdd;
  }
  if (!this.nextIf('_'))
    return NONE;

  for (let Idx = 0; Idx < NumTypesToAdd; ++Idx) {
    let ConvTy = this.popNode(K.Type);
    if (!ConvTy)
      return NONE;
    type.getChild(type.getNumChildren() - Idx - 1).addChild(ConvTy);
  }
  
  return this.createType(type);
}

  demangleMetatype(): Node {
  switch (this.nextChar()) {
    case 'a':
      return this.createWithPoppedType(K.TypeMetadataAccessFunction);
    case 'A':
      return this.createWithChild(K.ReflectionMetadataAssocTypeDescriptor,
                             this.popProtocolConformance());
    case 'b':
      return this.createWithPoppedType(
          K.CanonicalSpecializedGenericTypeMetadataAccessFunction);
    case 'B':
      return this.createWithChild(K.ReflectionMetadataBuiltinDescriptor,
                               this.popNode(K.Type));
    case 'c':
      return this.createWithChild(K.ProtocolConformanceDescriptor,
                             this.popProtocolConformance());
    case 'C': {
      let Ty = this.popNode(K.Type);
      if (!Ty || !this.isAnyGeneric(Ty.getChild(0).getKind()))
        return NONE;
      return this.createWithChild(K.ReflectionMetadataSuperclassDescriptor,
                             Ty.getChild(0));
    }
    case 'D':
      return this.createWithPoppedType(K.TypeMetadataDemanglingCache);
    case 'f':
      return this.createWithPoppedType(K.FullTypeMetadata);
    case 'F':
      return this.createWithChild(K.ReflectionMetadataFieldDescriptor,
                             this.popNode(K.Type));
    case 'g':
      return this.createWithChild(K.OpaqueTypeDescriptorAccessor,
                             this.popNode());
    case 'h':
      return this.createWithChild(K.OpaqueTypeDescriptorAccessorImpl,
                             this.popNode());
    case 'i':
      return this.createWithPoppedType(K.TypeMetadataInstantiationFunction);
    case 'I':
      return this.createWithPoppedType(K.TypeMetadataInstantiationCache);
    case 'j':
      return this.createWithChild(K.OpaqueTypeDescriptorAccessorKey,
                             this.popNode());
    case 'J':
      return this.createWithChild(K.NoncanonicalSpecializedGenericTypeMetadataCache, this.popNode());
    case 'k':
      return this.createWithChild(K.OpaqueTypeDescriptorAccessorVar,
                             this.popNode());
    case 'K':
      return this.createWithChild(K.MetadataInstantiationCache,
                             this.popNode());
    case 'l':
      return this.createWithPoppedType(
                          K.TypeMetadataSingletonInitializationCache);
    case 'L':
      return this.createWithPoppedType(K.TypeMetadataLazyCache);
    case 'm':
      return this.createWithPoppedType(K.Metaclass);
    case 'M':
      return this.createWithPoppedType(
          K.CanonicalSpecializedGenericMetaclass);
    case 'n':
      return this.createWithPoppedType(K.NominalTypeDescriptor);
    case 'N':
      return this.createWithPoppedType(
          K.NoncanonicalSpecializedGenericTypeMetadata);
    case 'o':
      return this.createWithPoppedType(K.ClassMetadataBaseOffset);
    case 'p':
      return this.createWithChild(K.ProtocolDescriptor, this.popProtocol());
    case 'P':
      return this.createWithPoppedType(K.GenericTypeMetadataPattern);
    case 'q':
      return this.createWithChild(K.Uniquable, this.popNode());
    case 'Q':
      return this.createWithChild(K.OpaqueTypeDescriptor, this.popNode());
    case 'r':
      return this.createWithPoppedType(K.TypeMetadataCompletionFunction);
    case 's':
      return this.createWithPoppedType(K.ObjCResilientClassStub);
    case 'S':
      return this.createWithChild(K.ProtocolSelfConformanceDescriptor,
                             this.popProtocol());
    case 't':
      return this.createWithPoppedType(K.FullObjCResilientClassStub);
    case 'u':
      return this.createWithPoppedType(K.MethodLookupFunction);
    case 'U':
      return this.createWithPoppedType(K.ObjCMetadataUpdateFunction);
    case 'V':
      return this.createWithChild(K.PropertyDescriptor,
                             this.popNode(this.isEntity));
    case 'X':
      return this.demanglePrivateContextDescriptor();
    case 'z':
      return this.createWithPoppedType(
          K.CanonicalPrespecializedGenericTypeCachingOnceToken);
    default:
      return NONE;
  }
}

  demanglePrivateContextDescriptor(): Node {
  switch (this.nextChar()) {
  case 'E': {
    let Extension = this.popContext();
    if (!Extension)
      return NONE;
    return this.createWithChild(K.ExtensionDescriptor, Extension);
  }
  case 'M': {
    let Module = this.popModule();
    if (!Module)
      return NONE;
    return this.createWithChild(K.ModuleDescriptor, Module);
  }
  case 'Y': {
    let Discriminator = this.popNode();
    if (!Discriminator)
      return NONE;
    let Context = this.popContext();
    if (!Context)
      return NONE;
    
    let node = this.createNode(K.AnonymousDescriptor);
    node.addChild(Context);
    node.addChild(Discriminator);
    return node;
  }
  case 'X': {
    let Context = this.popContext();
    if (!Context)
      return NONE;
    return this.createWithChild(K.AnonymousDescriptor, Context);
  }
  case 'A': {
    let path = this.popAssocTypePath();
    if (!path)
      return NONE;
    let base = this.popNode(K.Type);
    if (!base)
      return NONE;
    return this.createWithChildren(K.AssociatedTypeGenericParamRef,
                              base, path);
  }
  default:
    return NONE;
  }
}

  demangleArchetype(): Node {
  switch (this.nextChar()) {
  case 'a': {
    let Ident = this.popNode(K.Identifier);
    let ArcheTy = this.popTypeAndGetChild();
    let AssocTy = this.createType(
          this.createWithChildren(K.AssociatedTypeRef, ArcheTy, Ident));
    this.addSubstitution(AssocTy);
    return AssocTy;
  }
  case 'O': {
    let definingContext = this.popContext();
    return this.createWithChild(K.OpaqueReturnTypeOf, definingContext);
  }
  case 'o': {
    let index = this.demangleIndex();
    let boundGenericArgs: Node[] = [];
    let Retro = { v: NONE };
    if (!this.demangleBoundGenerics(boundGenericArgs, Retro))
      return NONE;
    let retroactiveConformances = Retro.v;
    let Name = this.popNode();
    if (!Name)
      return NONE;
    let opaque = this.createWithChildren(K.OpaqueType, Name,
                                   this.createNode(K.Index, index));
    let boundGenerics = this.createNode(K.TypeList);
    for (let i = boundGenericArgs.length; i-- > 0;)
      boundGenerics.addChild(boundGenericArgs[i]!);
    opaque.addChild(boundGenerics);
    if (retroactiveConformances)
      opaque.addChild(retroactiveConformances);
    
    let opaqueTy = this.createType(opaque);
    this.addSubstitution(opaqueTy);
    return opaqueTy;
  }
  case 'r': {
    return this.createType(this.createNode(K.OpaqueReturnType));
  }
  case 'R': {
    let ordinal = this.demangleIndex();
    if (ordinal < 0)
      return NONE;
    return this.createType(this.createWithChild(K.OpaqueReturnType,
                      this.createNode(K.OpaqueReturnTypeIndex, ordinal)));
  }

  case 'x': {
    let T = this.demangleAssociatedTypeSimple(NONE);
    this.addSubstitution(T);
    return T;
  }
      
  case 'X': {
    let T = this.demangleAssociatedTypeCompound(NONE);
    this.addSubstitution(T);
    return T;
  }

  case 'y': {
    let T = this.demangleAssociatedTypeSimple(this.demangleGenericParamIndex());
    this.addSubstitution(T);
    return T;
  }
  case 'Y': {
    let T = this.demangleAssociatedTypeCompound(
                                                 this.demangleGenericParamIndex());
    this.addSubstitution(T);
    return T;
  }

  case 'z': {
    let T = this.demangleAssociatedTypeSimple(
                                          this.getDependentGenericParamType(0, 0));
    this.addSubstitution(T);
    return T;
  }
  case 'Z': {
    let T = this.demangleAssociatedTypeCompound(
                                          this.getDependentGenericParamType(0, 0));
    this.addSubstitution(T);
    return T;
  }
  case 'p': {
    let CountTy = this.popTypeAndGetChild();
    let PatternTy = this.popTypeAndGetChild();
    let PackExpansionTy = this.createType(
          this.createWithChildren(K.PackExpansion, PatternTy, CountTy));
    return PackExpansionTy;
  }
  case 'e': {
    let PackTy = this.popTypeAndGetChild();
    let level = this.demangleIndex();
    if (level < 0)
      return NONE;

    let PackElementTy = this.createType(
          this.createWithChildren(K.PackElement, PackTy,
              this.createNode(K.PackElementLevel, level)));
    return PackElementTy;
  }
  case 'P':
    return this.popPack();
  case 'S':
    return this.popSILPack();
  default:
    return NONE;
  }
}

  demangleAssociatedTypeSimple(Base: Node): Node {
  let ATName = this.popAssocTypeName();
  let BaseTy;
  if (Base) {
    BaseTy = this.createType(Base);
  } else {
    BaseTy = this.popNode(K.Type);
  }
  return this.createType(this.createWithChildren(K.DependentMemberType,
                                       BaseTy, ATName));
}

  demangleAssociatedTypeCompound(Base: Node): Node {
  let AssocTyNames: Node[] = [];
  let firstElem = false;
  do {
    firstElem = (this.popNode(K.FirstElementMarker) != NONE);
    let AssocTyName = this.popAssocTypeName();
    if (!AssocTyName)
      return NONE;
    AssocTyNames.push(AssocTyName);
  } while (!firstElem);
    
  let BaseTy;
  if (Base)
    BaseTy = this.createType(Base);
  else
    BaseTy = this.popNode(K.Type);

  for (let AssocTy = AssocTyNames.pop()!; AssocTy; AssocTy = AssocTyNames.pop()!) {
    let depTy = this.createNode(K.DependentMemberType);
    depTy = this.addChild(depTy, BaseTy);
    BaseTy = this.createType(this.addChild(depTy, AssocTy));
  }
  return BaseTy;
}

  popAssocTypeName(): Node {
  let Proto = this.popNode(K.Type);
  if (Proto && !this.isProtocolNode(Proto))
    return NONE;

  // If we haven't seen a protocol, check for a symbolic reference.
  if (!Proto)
    Proto = this.popNode(K.ProtocolSymbolicReference);
  if (!Proto)
    Proto = this.popNode(K.ObjectiveCProtocolSymbolicReference);

  let Id = this.popNode(K.Identifier);
  let AssocTy = this.createWithChild(K.DependentAssociatedTypeRef, Id);
  this.addChild(AssocTy, Proto);
  return AssocTy;
}

  popAssocTypePath(): Node {
  let AssocTypePath = this.createNode(K.AssocTypePath);
  let firstElem = false;
  do {
    firstElem = (this.popNode(K.FirstElementMarker) != NONE);
    let AssocTy = this.popAssocTypeName();
    if (!AssocTy)
      return NONE;
    AssocTypePath.addChild(AssocTy);
  } while (!firstElem);
  AssocTypePath.reverseChildren();
  return AssocTypePath;
}

  getDependentGenericParamType(depth: number, index: number): Node {
  if (depth < 0 || index < 0)
    return NONE;

  let paramTy = this.createNode(K.DependentGenericParamType);
  paramTy.addChild(this.createNode(K.Index, depth));
  paramTy.addChild(this.createNode(K.Index, index));
  return paramTy;
}

  demangleGenericParamIndex(): Node {
  if (this.nextIf('d')) {
    let depth = this.demangleIndex() + 1;
    let index = this.demangleIndex();
    return this.getDependentGenericParamType(depth, index);
  }
  if (this.nextIf('z')) {
    return this.getDependentGenericParamType(0, 0);
  }
  if (this.nextIf('s')) {
    return this.createNode(K.ConstrainedExistentialSelf);
  }
  return this.getDependentGenericParamType(0, this.demangleIndex() + 1);
}

  popProtocolConformance(): Node {
  let GenSig = this.popNode(K.DependentGenericSignature);
  let Module = this.popModule();
  let Proto = this.popProtocol();
  let Type = this.popNode(K.Type);
  let Ident = NONE;
  if (!Type) {
    // Property behavior conformance
    Ident = this.popNode(K.Identifier);
    Type = this.popNode(K.Type);
  }
  if (GenSig) {
    Type = this.createType(this.createWithChildren(K.DependentGenericType,
                                         GenSig, Type));
  }
  let Conf = this.createWithChildren(K.ProtocolConformance,
                                        Type, Proto, Module);
  this.addChild(Conf, Ident);
  return Conf;
}

  demangleThunkOrSpecialization(): Node {
  const c = this.nextChar(); switch (c) {
    case 'c': return this.createWithChild(K.CurryThunk, this.popNode(this.isEntity));
    case 'j': return this.createWithChild(K.DispatchThunk, this.popNode(this.isEntity));
    case 'q': return this.createWithChild(K.MethodDescriptor, this.popNode(this.isEntity));
    case 'o': return this.createNode(K.ObjCAttribute);
    case 'O': return this.createNode(K.NonObjCAttribute);
    case 'D': return this.createNode(K.DynamicAttribute);
    case 'd': return this.createNode(K.DirectMethodReferenceAttribute);
    case 'E': return this.createNode(K.DistributedThunk);
    case 'F': return this.createNode(K.DistributedAccessor);
    case 'a': return this.createNode(K.PartialApplyObjCForwarder);
    case 'A': return this.createNode(K.PartialApplyForwarder);
    case 'm': return this.createNode(K.MergedFunction);
    case 'X': return this.createNode(K.DynamicallyReplaceableFunctionVar);
    case 'x': return this.createNode(K.DynamicallyReplaceableFunctionKey);
    case 'I': return this.createNode(K.DynamicallyReplaceableFunctionImpl);
    case 'Y':
    case 'Q': {
      let discriminator = this.demangleIndexAsNode();
      return this.createWithChild(
          c == 'Q' ? K.AsyncAwaitResumePartialFunction :
             /*'Y'*/ K.AsyncSuspendResumePartialFunction,
          discriminator);
    }
    case 'C': {
      let type = this.popNode(K.Type);
      return this.createWithChild(K.CoroutineContinuationPrototype, type);
    }
    case 'z':
    case 'Z': {
      let flagMode = this.demangleIndexAsNode();
      let sig = this.popNode(K.DependentGenericSignature);
      let resultType = this.popNode(K.Type);
      let implType = this.popNode(K.Type);
      let node = this.createWithChildren(c == 'z'
                                  ? K.ObjCAsyncCompletionHandlerImpl
                                  : K.PredefinedObjCAsyncCompletionHandlerImpl,
                                implType, resultType, flagMode);
      if (sig)
        this.addChild(node, sig);
      return node;
    }
    case 'V': {
      let Base = this.popNode(this.isEntity);
      let Derived = this.popNode(this.isEntity);
      return this.createWithChildren(K.VTableThunk, Derived, Base);
    }
    case 'W': {
      let Entity = this.popNode(this.isEntity);
      let Conf = this.popProtocolConformance();
      return this.createWithChildren(K.ProtocolWitness, Conf, Entity);
    }
    case 'S':
      return this.createWithChild(K.ProtocolSelfConformanceWitness,
                             this.popNode(this.isEntity));
    case 'R':
    case 'r':
    case 'y': {
      let kind;
      if (c == 'R') kind = K.ReabstractionThunkHelper;
      else if (c == 'y') kind = K.ReabstractionThunkHelperWithSelf;
      else kind = K.ReabstractionThunk;
      let Thunk = this.createNode(kind);
      const GenSig = this.popNode(K.DependentGenericSignature);
      if (GenSig)
        this.addChild(Thunk, GenSig);
      if (kind == K.ReabstractionThunkHelperWithSelf)
        this.addChild(Thunk, this.popNode(K.Type));
      this.addChild(Thunk, this.popNode(K.Type));
      this.addChild(Thunk, this.popNode(K.Type));
      return Thunk;
    }
    case 'g':
      return this.demangleGenericSpecialization(K.GenericSpecialization);
    case 'G':
      return this.demangleGenericSpecialization(K.GenericSpecializationNotReAbstracted);
    case 'B':
      return this.demangleGenericSpecialization(K.GenericSpecializationInResilienceDomain);
    case 's':
      return this.demangleGenericSpecialization(
          K.GenericSpecializationPrespecialized);
    case 'i':
      return this.demangleGenericSpecialization(K.InlinedGenericFunction);
    case 'p': {
      let Spec = this.demangleSpecAttributes(K.GenericPartialSpecialization);
      let Param = this.createWithChild(K.GenericSpecializationParam,
                                          this.popNode(K.Type));
      return this.addChild(Spec, Param);
    }
    case'P': {
      let Spec = this.demangleSpecAttributes(K.GenericPartialSpecializationNotReAbstracted);
      let Param = this.createWithChild(K.GenericSpecializationParam,
                                          this.popNode(K.Type));
      return this.addChild(Spec, Param);
    }
    case'f':
      return this.demangleFunctionSpecialization();
    case 'K':
    case 'k': {
      let nodeKind = c == 'K' ? K.KeyPathGetterThunkHelper
                               : K.KeyPathSetterThunkHelper;

      let isSerialized = this.nextIf('q');

      let types: Node[] = [];
      let node = this.popNode();
      if (!node || node.getKind() != K.Type)
        return NONE;
      do {
        types.push(node);
        node = this.popNode();
      } while (node && node.getKind() == K.Type);
      
      let result;
      if (node) {
        if (node.getKind() == K.DependentGenericSignature) {
          let decl = this.popNode();
          if (!decl)
            return NONE;
          result = this.createWithChildren(nodeKind, decl, /*sig*/ node);
        } else {
          result = this.createWithChild(nodeKind, /*decl*/ node);
        }
      } else {
        return NONE;
      }
      for (let i = types.length - 1; i >= 0; --i) {
        result.addChild(types[i]!);
      }

      if (isSerialized)
        result.addChild(this.createNode(K.IsSerialized));

      return result;
    }
    case 'l': {
      let assocTypeName = this.popAssocTypeName();
      if (!assocTypeName)
        return NONE;

      return this.createWithChild(K.AssociatedTypeDescriptor,
                             assocTypeName);
    }
    case 'L':
      return this.createWithChild(K.ProtocolRequirementsBaseDescriptor,
                             this.popProtocol());
    case 'M':
      return this.createWithChild(K.DefaultAssociatedTypeMetadataAccessor,
                             this.popAssocTypeName());

    case 'n': {
      let requirementTy = this.popProtocol();
      let conformingType = this.popAssocTypePath();
      let protoTy = this.popNode(K.Type);
      return this.createWithChildren(K.AssociatedConformanceDescriptor,
                                protoTy, conformingType, requirementTy);
    }

    case 'N': {
      let requirementTy = this.popProtocol();
      let assocTypePath = this.popAssocTypePath();
      let protoTy = this.popNode(K.Type);
      return this.createWithChildren(
                            K.DefaultAssociatedConformanceAccessor,
                            protoTy, assocTypePath, requirementTy);
    }

    case 'b': {
      let requirementTy = this.popProtocol();
      let protoTy = this.popNode(K.Type);
      return this.createWithChildren(K.BaseConformanceDescriptor,
                                protoTy, requirementTy);
    }

    case 'H':
    case 'h': {
      let nodeKind = c == 'H' ? K.KeyPathEqualsThunkHelper
                               : K.KeyPathHashThunkHelper;

      let isSerialized = this.nextIf('q');

      let genericSig = NONE;
      let types: Node[] = [];
      
      let node = this.popNode();
      if (node) {
        if (node.getKind() == K.DependentGenericSignature) {
          genericSig = node;
        } else if (node.getKind() == K.Type) {
          types.push(node);
        } else {
          return NONE;
        }
      } else {
        return NONE;
      }
      
      for (let node = this.popNode(); node; node = this.popNode()) {
        if (node.getKind() != K.Type) {
          return NONE;
        }
        types.push(node);
      }
      
      let result = this.createNode(nodeKind);
      for (let i = types.length - 1; i >= 0; --i) {
        result.addChild(types[i]!);
      }
      if (genericSig)
        result.addChild(genericSig);

      if (isSerialized)
        result.addChild(this.createNode(K.IsSerialized));

      return result;
    }
    case 'v': {
      let Idx = this.demangleIndex();
      if (Idx < 0)
        return NONE;
      if (this.nextChar() == 'r')
        return this.createNode(K.OutlinedReadOnlyObject, Idx);
      return this.createNode(K.OutlinedVariable, Idx);
    }
    case 'e': {
      let Params = this.demangleBridgedMethodParams();
      if (Params.length === 0)
        return NONE;
      return this.createNode(K.OutlinedBridgedMethod, Params);
    }
    case 'u': return this.createNode(K.AsyncFunctionPointer);
    case 'U': {
      let globalActor = this.popNode(K.Type);
      if (!globalActor)
        return NONE;
      
      let reabstraction = this.popNode();
      if (!reabstraction)
        return NONE;
      
      let node = this.createNode(K.ReabstractionThunkHelperWithGlobalActor);
      node.addChild(reabstraction);
      node.addChild(globalActor);
      return node;
    }
    case 'J':
      switch (this.peekChar()) {
      case 'S':
        this.nextChar();
        return this.demangleAutoDiffSubsetParametersThunk();
      case 'O':
        this.nextChar();
        return this.demangleAutoDiffSelfReorderingReabstractionThunk();
      case 'V':
        this.nextChar();
        return this.demangleAutoDiffFunctionOrSimpleThunk(
            K.AutoDiffDerivativeVTableThunk);
      default:
        return this.demangleAutoDiffFunctionOrSimpleThunk(
            K.AutoDiffFunction);
      }
    case 'w':
      switch (this.nextChar()) {
      case 'b': return this.createNode(K.BackDeploymentThunk);
      case 'B': return this.createNode(K.BackDeploymentFallback);
      case 'S': return this.createNode(K.HasSymbolQuery);
      default:
        return NONE;
      }
    default:
      return NONE;
  }
}

  demangleAutoDiffFunctionOrSimpleThunk(nodeKind: Kind): Node {
  let result = this.createNode(nodeKind);
  for (let originalNode = this.popNode(); originalNode; originalNode = this.popNode())
    result = this.addChild(result, originalNode);
  result.reverseChildren();
  let kind = this.demangleAutoDiffFunctionKind();
  result = this.addChild(result, kind);
  result = this.addChild(result, this.demangleIndexSubset());
  if (!this.nextIf('p'))
    return NONE;
  result = this.addChild(result, this.demangleIndexSubset());
  if (!this.nextIf('r'))
    return NONE;
  return result;
}

  demangleAutoDiffFunctionKind(): Node {
  let kind = this.nextChar();
  if (kind != 'f' && kind != 'r' && kind != 'd' && kind != 'p')
    return NONE;
  return this.createNode(K.AutoDiffFunctionKind, charCode(kind));
}

  demangleAutoDiffSubsetParametersThunk(): Node {
  let result = this.createNode(K.AutoDiffSubsetParametersThunk);
  for (let node = this.popNode(); node; node = this.popNode())
    result = this.addChild(result, node);
  result.reverseChildren();
  let kind = this.demangleAutoDiffFunctionKind();
  result = this.addChild(result, kind);
  result = this.addChild(result, this.demangleIndexSubset());
  if (!this.nextIf('p'))
    return NONE;
  result = this.addChild(result, this.demangleIndexSubset());
  if (!this.nextIf('r'))
    return NONE;
  result = this.addChild(result, this.demangleIndexSubset());
  if (!this.nextIf('P'))
    return NONE;
  return result;
}

  demangleAutoDiffSelfReorderingReabstractionThunk(): Node {
  let result = this.createNode(
      K.AutoDiffSelfReorderingReabstractionThunk);
  this.addChild(result, this.popNode(K.DependentGenericSignature));
  result = this.addChild(result, this.popNode(K.Type));
  result = this.addChild(result, this.popNode(K.Type));
  if (result)
    result.reverseChildren();
  result = this.addChild(result, this.demangleAutoDiffFunctionKind());
  return result;
}

  demangleDifferentiabilityWitness(): Node {
  let result = this.createNode(K.DifferentiabilityWitness);
  let optionalGenSig = this.popNode(K.DependentGenericSignature);
  for (let node = this.popNode(); node; node = this.popNode())
    result = this.addChild(result, node);
  result.reverseChildren();
  let kind = 0;
  const kc = this.nextChar();
  switch (kc) {
  case 'f': case 'r': case 'd': case 'l': kind = charCode(kc); break;
  default: return NONE;
  }
  result = this.addChild(
      result, this.createNode(K.Index, kind));
  result = this.addChild(result, this.demangleIndexSubset());
  if (!this.nextIf('p'))
    return NONE;
  result = this.addChild(result, this.demangleIndexSubset());
  if (!this.nextIf('r'))
    return NONE;
  this.addChild(result, optionalGenSig);
  return result;
}

  demangleIndexSubset(): Node {
  let str = '';
  for (let c = this.peekChar(); c == 'S' || c == 'U'; c = this.peekChar()) {
    str += c;
    this.nextChar();
  }
  if (str.length === 0)
    return NONE;
  return this.createNode(K.IndexSubset, str);
}

  demangleDifferentiableFunctionType(): Node {
  let kind = 0;
  const kc = this.nextChar();
  switch (kc) {
  case 'f': case 'r': case 'd': case 'l': kind = charCode(kc); break;
  default: return NONE;
  }
  return this.createNode(
      K.DifferentiableFunctionType, kind);
}

  demangleLifetimeDependenceKind(isSelfDependence: boolean): Node {
  let kind = 0;
  const kc = this.nextChar();
  switch (kc) {
  case 's': case 'i': kind = charCode(kc); break;
  default:
    return NONE;
  }
  if (isSelfDependence) {
    return this.createNode(K.SelfLifetimeDependence,
                      kind);
  }
  let node = this.createWithChildren(K.ParamLifetimeDependence,
                                 this.createNode(K.Index, kind),
                                 this.popTypeAndGetChild());
  return this.createType(node);
}

  demangleBridgedMethodParams(): string {
  if (this.nextIf('_'))
    return '';

  let Str = '';

  let kind = this.nextChar();
  switch (kind) {
  default:
    return '';
  case 'o': case 'p': case 'a': case 'm':
    Str += kind;
  }

  while (!this.nextIf('_')) {
    let c = this.nextChar();
    if (c != 'n' && c != 'b' && c != 'g')
      return '';
    Str += c;
  }
  return Str;
}

  demangleGenericSpecialization(SpecKind: Kind): Node {
  let Spec = this.demangleSpecAttributes(SpecKind);
  if (!Spec)
    return NONE;
  let TyList = this.popTypeList();
  if (!TyList)
    return NONE;
  for (const Ty of TyList.children) {
    Spec.addChild(this.createWithChild(K.GenericSpecializationParam, Ty));
  }
  return Spec;
}

  demangleFunctionSpecialization(): Node {
  let Spec = this.demangleSpecAttributes(
        K.FunctionSignatureSpecialization);
  while (Spec && !this.nextIf('_')) {
    Spec = this.addChild(Spec, this.demangleFuncSpecParam(K.FunctionSignatureSpecializationParam));
  }
  if (!this.nextIf('n'))
    Spec = this.addChild(Spec, this.demangleFuncSpecParam(K.FunctionSignatureSpecializationReturn));

  if (!Spec)
    return NONE;

  // Add the required parameters in reverse order.
  for (let Idx = 0, Num = Spec.getNumChildren(); Idx < Num; ++Idx) {
    let Param = Spec.getChild(Num - Idx - 1);
    if (Param.getKind() != K.FunctionSignatureSpecializationParam)
      continue;

    if (Param.getNumChildren() == 0)
      continue;
    let KindNd = Param.getFirstChild();
    /* assert */ void 0;
    let ParamKind = KindNd.getIndex() as FunctionSigSpecializationParamKind;
    switch (ParamKind) {
      case FunctionSigSpecializationParamKind.ConstantPropFunction:
      case FunctionSigSpecializationParamKind.ConstantPropGlobal:
      case FunctionSigSpecializationParamKind.ConstantPropString:
      case FunctionSigSpecializationParamKind.ConstantPropKeyPath:
      case FunctionSigSpecializationParamKind.ClosureProp: {
        let FixedChildren = Param.getNumChildren();
        for (let Ty = this.popNode(K.Type); Ty; Ty = this.popNode(K.Type)) {
          if (ParamKind != FunctionSigSpecializationParamKind.ClosureProp &&
              ParamKind != FunctionSigSpecializationParamKind.ConstantPropKeyPath)
            return NONE;
          Param = this.addChild(Param, Ty);
        }
        let Name = this.popNode(K.Identifier);
        if (!Name)
          return NONE;
        let Text = Name.getText();
        if (ParamKind ==
                FunctionSigSpecializationParamKind.ConstantPropString &&
            (Text.length !== 0) && Text[0] == '_') {
          // A '_' escapes a leading digit or '_' of a string constant.
          Text = Text.slice(1);
        }
        this.addChild(Param, this.createNodeWithAllocatedText(
          K.FunctionSignatureSpecializationParamPayload, Text));
        Param.reverseChildren(FixedChildren);
        break;
      }
      default:
        break;
    }
  }
  return Spec;
}

  demangleFuncSpecParam(kind: Kind): Node {
  let Param = this.createNode(kind);
  switch (this.nextChar()) {
    case 'n':
      return Param;
    case 'c':
      // Consumes an identifier and multiple type parameters.
      // The parameters will be added later.
      return this.addChild(Param, this.createNode(
        K.FunctionSignatureSpecializationParamKind,
        FunctionSigSpecializationParamKind.ClosureProp));
    case 'p': {
      switch (this.nextChar()) {
        case 'f':
          // Consumes an identifier parameter, which will be added later.
          return this.addChild(
              Param,
              this.createNode(K.FunctionSignatureSpecializationParamKind,
                         FunctionSigSpecializationParamKind.ConstantPropFunction));
        case 'g':
          // Consumes an identifier parameter, which will be added later.
          return this.addChild(
              Param,
              this.createNode(
                  K.FunctionSignatureSpecializationParamKind,
                  FunctionSigSpecializationParamKind.ConstantPropGlobal));
        case 'i':
          return this.addFuncSpecParamNumber(Param,
                    FunctionSigSpecializationParamKind.ConstantPropInteger);
        case 'd':
          return this.addFuncSpecParamNumber(Param,
                      FunctionSigSpecializationParamKind.ConstantPropFloat);
        case 's': {
          // Consumes an identifier parameter (the string constant),
          // which will be added later.
          let Encoding = '';
          switch (this.nextChar()) {
            case 'b': Encoding = "u8"; break;
            case 'w': Encoding = "u16"; break;
            case 'c': Encoding = "objc"; break;
            default: return NONE;
          }
          this.addChild(Param,
                   this.createNode(
                       K.FunctionSignatureSpecializationParamKind,
                       FunctionSigSpecializationParamKind.ConstantPropString));
          return this.addChild(Param, this.createNode(
                  K.FunctionSignatureSpecializationParamPayload,
                  Encoding));
        }
        case 'k': {
          // Consumes two types and a SHA1 identifier.
          return this.addChild(
              Param,
              this.createNode(K.FunctionSignatureSpecializationParamKind,
                         FunctionSigSpecializationParamKind.ConstantPropKeyPath));
        }
        default:
          return NONE;
      }
    }
    case 'e': {
      let Value =
          FunctionSigSpecializationParamKind.ExistentialToGeneric;
      if (this.nextIf('D'))
        Value |= FunctionSigSpecializationParamKind.Dead;
      if (this.nextIf('G'))
        Value |=
            FunctionSigSpecializationParamKind.OwnedToGuaranteed;
      if (this.nextIf('O'))
        Value |=
            FunctionSigSpecializationParamKind.GuaranteedToOwned;
      if (this.nextIf('X'))
        Value |= FunctionSigSpecializationParamKind.SROA;
      return this.addChild(
          Param,
          this.createNode(K.FunctionSignatureSpecializationParamKind,
                     Value));
    }
    case 'd': {
      let Value = FunctionSigSpecializationParamKind.Dead;
      if (this.nextIf('G'))
        Value |= FunctionSigSpecializationParamKind.OwnedToGuaranteed;
      if (this.nextIf('O'))
        Value |=
            FunctionSigSpecializationParamKind.GuaranteedToOwned;
      if (this.nextIf('X'))
        Value |= FunctionSigSpecializationParamKind.SROA;
      return this.addChild(Param, this.createNode(
                  K.FunctionSignatureSpecializationParamKind, Value));
    }
    case 'g': {
      let Value = FunctionSigSpecializationParamKind.OwnedToGuaranteed;
      if (this.nextIf('X'))
        Value |= FunctionSigSpecializationParamKind.SROA;
      return this.addChild(Param, this.createNode(
                  K.FunctionSignatureSpecializationParamKind, Value));
    }
    case 'o': {
      let Value =
          FunctionSigSpecializationParamKind.GuaranteedToOwned;
      if (this.nextIf('X'))
        Value |= FunctionSigSpecializationParamKind.SROA;
      return this.addChild(
          Param,
          this.createNode(K.FunctionSignatureSpecializationParamKind,
                     Value));
    }
    case 'x':
      return this.addChild(Param, this.createNode(
                K.FunctionSignatureSpecializationParamKind,
                FunctionSigSpecializationParamKind.SROA));
    case 'i':
      return this.addChild(Param, this.createNode(
                K.FunctionSignatureSpecializationParamKind,
                FunctionSigSpecializationParamKind.BoxToValue));
    case 's':
      return this.addChild(Param, this.createNode(
                K.FunctionSignatureSpecializationParamKind,
                FunctionSigSpecializationParamKind.BoxToStack));
    case 'r':
      return this.addChild(
          Param,
          this.createNode(K.FunctionSignatureSpecializationParamKind,
                     FunctionSigSpecializationParamKind.InOutToOut));
    default:
      return NONE;
  }
}

  addFuncSpecParamNumber(Param: Node, Kind: FunctionSigSpecializationParamKind): Node {
  Param.addChild(this.createNode(
        K.FunctionSignatureSpecializationParamKind, Kind));
  let Str = '';
  while (isDigit(this.peekChar())) {
    Str += this.nextChar();
  }
  if (Str.length === 0)
    return NONE;
  return this.addChild(Param, this.createNode(
     K.FunctionSignatureSpecializationParamPayload, Str));
}

  demangleSpecAttributes(SpecKind: Kind): Node {
  let metatypeParamsRemoved = this.nextIf('m');
  let isSerialized = this.nextIf('q');
  let asyncRemoved = this.nextIf('a');

  let PassID = charCode(this.nextChar()) - 48;
  if (PassID < 0 || PassID >= 10) {
    return NONE;
  }

  let SpecNd = this.createNode(SpecKind);

  if (metatypeParamsRemoved)
    SpecNd.addChild(this.createNode(K.MetatypeParamsRemoved));

  if (isSerialized)
    SpecNd.addChild(this.createNode(K.IsSerialized));

  if (asyncRemoved)
    SpecNd.addChild(this.createNode(K.AsyncRemoved));

  SpecNd.addChild(this.createNode(K.SpecializationPassID, PassID));
  return SpecNd;
}

  demangleWitness(): Node {
  const c = this.nextChar(); switch (c) {
    case 'C':
      return this.createWithChild(K.EnumCase,
                             this.popNode(this.isEntity));
    case 'V':
      return this.createWithChild(K.ValueWitnessTable,
                             this.popNode(K.Type));
    case 'v': {
      let Directness: number;
      switch (this.nextChar()) {
        case 'd': Directness = N.Directness.Direct; break;
        case 'i': Directness = N.Directness.Indirect; break;
        default: return NONE;
      }
      return this.createWithChildren(K.FieldOffset,
                        this.createNode(K.Directness, Directness),
                        this.popNode(this.isEntity));
    }
    case 'S':
      return this.createWithChild(K.ProtocolSelfConformanceWitnessTable,
                             this.popProtocol());
    case 'P':
      return this.createWithChild(K.ProtocolWitnessTable,
                             this.popProtocolConformance());
    case 'p':
      return this.createWithChild(K.ProtocolWitnessTablePattern,
                             this.popProtocolConformance());
    case 'G':
      return this.createWithChild(K.GenericProtocolWitnessTable,
                             this.popProtocolConformance());
    case 'I':
      return this.createWithChild(
                  K.GenericProtocolWitnessTableInstantiationFunction,
                  this.popProtocolConformance());

    case 'r':
      return this.createWithChild(K.ResilientProtocolWitnessTable,
                             this.popProtocolConformance());

    case 'l': {
      let Conf = this.popProtocolConformance();
      let Type = this.popNode(K.Type);
      return this.createWithChildren(K.LazyProtocolWitnessTableAccessor,
                                Type, Conf);
    }
    case 'L': {
      let Conf = this.popProtocolConformance();
      let Type = this.popNode(K.Type);
      return this.createWithChildren(
               K.LazyProtocolWitnessTableCacheVariable, Type, Conf);
    }
    case 'a':
      return this.createWithChild(K.ProtocolWitnessTableAccessor,
                             this.popProtocolConformance());
    case 't': {
      let Name = this.popNode(this.isDeclName);
      let Conf = this.popProtocolConformance();
      return this.createWithChildren(K.AssociatedTypeMetadataAccessor,
                                Conf, Name);
    }
    case 'T': {
      let ProtoTy = this.popNode(K.Type);
      let ConformingType = this.popAssocTypePath();
      let Conf = this.popProtocolConformance();
      return this.createWithChildren(K.AssociatedTypeWitnessTableAccessor,
                                Conf, ConformingType, ProtoTy);
    }
    case 'b': {
      let ProtoTy = this.popNode(K.Type);
      let Conf = this.popProtocolConformance();
      return this.createWithChildren(K.BaseWitnessTableAccessor,
                                Conf, ProtoTy);
    }
    case 'O': {
      switch (this.nextChar()) {
      case 'C': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedInitializeWithCopyNoValueWitness,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedInitializeWithCopyNoValueWitness,
                               this.popNode(K.Type));
      }
      case 'D': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedAssignWithTakeNoValueWitness,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedAssignWithTakeNoValueWitness,
                               this.popNode(K.Type));
      }
      case 'F': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedAssignWithCopyNoValueWitness,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedAssignWithCopyNoValueWitness,
                               this.popNode(K.Type));
      }
      case 'H': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedDestroyNoValueWitness,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedDestroyNoValueWitness,
                               this.popNode(K.Type));
      }
      case 'y': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedCopy,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedCopy,
                               this.popNode(K.Type));
      }
      case 'e': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedConsume,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedConsume,
                               this.popNode(K.Type));
      }
      case 'r': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedRetain,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedRetain,
                               this.popNode(K.Type));
      }
      case 's': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedRelease,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedRelease,
                               this.popNode(K.Type));
      }
      case 'b': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedInitializeWithTake,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedInitializeWithTake,
                               this.popNode(K.Type));
      }
      case 'c': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedInitializeWithCopy,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedInitializeWithCopy,
                               this.popNode(K.Type));
      }
      case 'd': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedAssignWithTake,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedAssignWithTake,
                               this.popNode(K.Type));
      }
      case 'f': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedAssignWithCopy,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedAssignWithCopy,
                               this.popNode(K.Type));
      }
      case 'h': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedDestroy,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedDestroy,
                               this.popNode(K.Type));
      }
      case 'g': {
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedEnumGetTag,
                                    this.popNode(K.Type), sig);
        return this.createWithChild(K.OutlinedEnumGetTag,
                               this.popNode(K.Type));
      }

      case 'i': {
        let enumCaseIdx = this.demangleIndexAsNode();
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedEnumTagStore,
                                    this.popNode(K.Type), sig,
                                    enumCaseIdx);
        return this.createWithChildren(K.OutlinedEnumTagStore,
                                  this.popNode(K.Type), enumCaseIdx);
      }
      case 'j': {
        let enumCaseIdx = this.demangleIndexAsNode();
        const sig = this.popNode(K.DependentGenericSignature);
        if (sig)
          return this.createWithChildren(K.OutlinedEnumProjectDataForLoad,
                                    this.popNode(K.Type), sig,
                                    enumCaseIdx);
        return this.createWithChildren(K.OutlinedEnumProjectDataForLoad,
                                  this.popNode(K.Type), enumCaseIdx);
      }

      default:
        return NONE;
      }
    }
    case 'Z':
    case 'z': {
      let declList = this.createNode(K.GlobalVariableOnceDeclList);
      let vars: Node[] = [];
      for (let sig = this.popNode(K.FirstElementMarker); sig; sig = this.popNode(K.FirstElementMarker)) {
        let identifier = this.popNode(this.isDeclName);
        if (!identifier)
          return NONE;
        vars.push(identifier);
      }
      for (let i = vars.length - 1; i >= 0; --i) {
        declList.addChild(vars[i]!);
      }

      
      let context = this.popContext();
      if (!context)
        return NONE;
      let kind = c == 'Z'
        ? K.GlobalVariableOnceFunction
        : K.GlobalVariableOnceToken;
      return this.createWithChildren(kind,
                                context,
                                declList);
    }
    case 'J':
      return this.demangleDifferentiabilityWitness();
    default:
      return NONE;
  }
}

  demangleSpecialType(): Node {
  const specialChar = this.nextChar(); switch (specialChar) {
    case 'E':
      return this.popFunctionType(K.NoEscapeFunctionType);
    case 'A':
      return this.popFunctionType(K.EscapingAutoClosureType);
    case 'f':
      return this.popFunctionType(K.ThinFunctionType);
    case 'K':
      return this.popFunctionType(K.AutoClosureType);
    case 'U':
      return this.popFunctionType(K.UncurriedFunctionType);
    case 'L':
      return this.popFunctionType(K.EscapingObjCBlock);
    case 'B':
      return this.popFunctionType(K.ObjCBlock);
    case 'C':
      return this.popFunctionType(K.CFunctionPointer);
    case 'g':
    case 'G':
      return this.demangleExtendedExistentialShape(specialChar);
    case 'j':
      return this.demangleSymbolicExtendedExistentialType();
    case 'z':
      switch (this.nextChar()) {
      case 'B':
        return this.popFunctionType(K.ObjCBlock, true);
      case 'C':
        return this.popFunctionType(K.CFunctionPointer, true);
      default:
        return NONE;
      }
    case 'o':
      return this.createType(this.createWithChild(K.Unowned,
                                        this.popNode(K.Type)));
    case 'u':
      return this.createType(this.createWithChild(K.Unmanaged,
                                        this.popNode(K.Type)));
    case 'w':
      return this.createType(this.createWithChild(K.Weak,
                                        this.popNode(K.Type)));
    case 'b':
      return this.createType(this.createWithChild(K.SILBoxType,
                                        this.popNode(K.Type)));
    case 'D':
      return this.createType(this.createWithChild(K.DynamicSelf,
                                        this.popNode(K.Type)));
    case 'M': {
      let MTR = this.demangleMetatypeRepresentation();
      let Type = this.popNode(K.Type);
      return this.createType(this.createWithChildren(K.Metatype, MTR, Type));
    }
    case 'm': {
      let MTR = this.demangleMetatypeRepresentation();
      let Type = this.popNode(K.Type);
      return this.createType(this.createWithChildren(K.ExistentialMetatype,
                                           MTR, Type));
    }
    case 'P': {
      let Reqs = this.demangleConstrainedExistentialRequirementList();
      let Base = this.popNode(K.Type);
      return this.createType(
          this.createWithChildren(K.ConstrainedExistential, Base, Reqs));
    }
    case 'p':
      return this.createType(this.createWithChild(K.ExistentialMetatype,
                                        this.popNode(K.Type)));
    case 'c': {
      let Superclass = this.popNode(K.Type);
      let Protocols = this.demangleProtocolList();
      return this.createType(this.createWithChildren(K.ProtocolListWithClass,
                                           Protocols, Superclass));
    }
    case 'l': {
      let Protocols = this.demangleProtocolList();
      return this.createType(this.createWithChild(K.ProtocolListWithAnyObject,
                                        Protocols));
    }
    case 'X':
    case 'x': {
      // SIL box types.
      let signature = NONE, genericArgs = NONE;
      if (specialChar == 'X') {
        signature = this.popNode(K.DependentGenericSignature);
        if (!signature)
          return NONE;
        genericArgs = this.popTypeList();
        if (!genericArgs)
          return NONE;
      }
      
      let fieldTypes = this.popTypeList();
      if (!fieldTypes)
        return NONE;
      // Build layout.
      let layout = this.createNode(K.SILBoxLayout);
      for (let i = 0, e = fieldTypes.getNumChildren(); i < e; ++i) {
        let fieldType = fieldTypes.getChild(i);
        /* assert */ void 0;
        let isMutable = false;
        // 'inout' typelist mangling is used to represent mutable fields.
        if (fieldType.getChild(0).getKind() == K.InOut) {
          isMutable = true;
          fieldType = this.createType(fieldType.getChild(0).getChild(0));
        }
        let field = this.createNode(isMutable
                                         ? K.SILBoxMutableField
                                         : K.SILBoxImmutableField);
        field.addChild(fieldType);
        layout.addChild(field);
      }
      let boxTy = this.createNode(K.SILBoxTypeWithLayout);
      boxTy.addChild(layout);
      if (signature) {
        boxTy.addChild(signature);
        /* assert */ void 0;
        boxTy.addChild(genericArgs);
      }
      return this.createType(boxTy);
    }
    case 'Y':
      return this.demangleAnyGenericType(K.OtherNominalType);
    case 'Z': {
      let types = this.popTypeList();
      let name = this.popNode(K.Identifier);
      let parent = this.popContext();
      let anon = this.createNode(K.AnonymousContext);
      anon = this.addChild(anon, name);
      anon = this.addChild(anon, parent);
      anon = this.addChild(anon, types);
      return anon;
    }
    case 'e':
      return this.createType(this.createNode(K.ErrorType));
    case 'S':
      // Sugared type for debugger.
      switch (this.nextChar()) {
      case 'q':
        return this.createType(this.createWithChild(K.SugaredOptional,
                                          this.popNode(K.Type)));
      case 'a':
        return this.createType(this.createWithChild(K.SugaredArray,
                                          this.popNode(K.Type)));
      case 'D': {
        let value = this.popNode(K.Type);
        let key = this.popNode(K.Type);
        return this.createType(this.createWithChildren(K.SugaredDictionary,
                                             key, value));
      }
      case 'p':
        return this.createType(this.createWithChild(K.SugaredParen,
                                          this.popNode(K.Type)));
      default:
        return NONE;
      }
    default:
      return NONE;
  }
}

  demangleSymbolicExtendedExistentialType(): Node {
  let retroactiveConformances = this.popRetroactiveConformances();

  let args = this.createNode(K.TypeList);
  for (let ty = this.popNode(K.Type); ty; ty = this.popNode(K.Type)) {
    args.addChild(ty);
  }
  args.reverseChildren();

  let shape = this.popNode();
  if (!shape)
    return NONE;
  if (shape.getKind() !=
        K.UniqueExtendedExistentialTypeShapeSymbolicReference &&
      shape.getKind() !=
        K.NonUniqueExtendedExistentialTypeShapeSymbolicReference)
    return NONE;

  let existentialType;
  if (!retroactiveConformances) {
    existentialType =
      this.createWithChildren(K.SymbolicExtendedExistentialType,
                         shape, args);
  } else {
    existentialType =
      this.createWithChildren(K.SymbolicExtendedExistentialType,
                         shape, args, retroactiveConformances);
  }
  return this.createType(existentialType);
}

  demangleExtendedExistentialShape(nodeKind: string): Node {
  /* assert */ void 0;

  let type = this.popNode(K.Type);

  let genSig = NONE;
  if (nodeKind == 'G')
    genSig = this.popNode(K.DependentGenericSignature);

  if (genSig) {
    return this.createWithChildren(K.ExtendedExistentialTypeShape,
                              genSig, type);
  } else {
    return this.createWithChild(K.ExtendedExistentialTypeShape, type);
  }
}

  demangleMetatypeRepresentation(): Node {
  switch (this.nextChar()) {
    case 't':
      return this.createNode(K.MetatypeRepresentation, "@thin");
    case 'T':
      return this.createNode(K.MetatypeRepresentation, "@thick");
    case 'o':
      return this.createNode(K.MetatypeRepresentation,
                                 "@objc_metatype");
    default:
      return NONE;
  }
}

  demangleAccessor(ChildNode: Node): Node {
  let Kind;
  switch (this.nextChar()) {
    case 'm': Kind = K.MaterializeForSet; break;
    case 's': Kind = K.Setter; break;
    case 'g': Kind = K.Getter; break;
    case 'G': Kind = K.GlobalGetter; break;
    case 'w': Kind = K.WillSet; break;
    case 'W': Kind = K.DidSet; break;
    case 'r': Kind = K.ReadAccessor; break;
    case 'M': Kind = K.ModifyAccessor; break;
    case 'i': Kind = K.InitAccessor; break;
    case 'a':
      switch (this.nextChar()) {
        case 'O': Kind = K.OwningMutableAddressor; break;
        case 'o': Kind = K.NativeOwningMutableAddressor; break;
        case 'P': Kind = K.NativePinningMutableAddressor; break;
        case 'u': Kind = K.UnsafeMutableAddressor; break;
        default: return NONE;
      }
      break;
    case 'l':
      switch (this.nextChar()) {
        case 'O': Kind = K.OwningAddressor; break;
        case 'o': Kind = K.NativeOwningAddressor; break;
        case 'p': Kind = K.NativePinningAddressor; break;
        case 'u': Kind = K.UnsafeAddressor; break;
        default: return NONE;
      }
      break;
    case 'p': // Pseudo-accessor referring to the variable/subscript itself
      return ChildNode;
    default: return NONE;
  }
  let Entity = this.createWithChild(Kind, ChildNode);
  return Entity;
}

  demangleFunctionEntity(): Node {
  let Args = '';

  let Kind: Kind;

  switch (this.nextChar()) {
    case 'D': Args = 'None'; Kind = K.Deallocator; break;
    case 'd': Args = 'None'; Kind = K.Destructor; break;
    case 'E': Args = 'None'; Kind = K.IVarDestroyer; break;
    case 'e': Args = 'None'; Kind = K.IVarInitializer; break;
    case 'i': Args = 'None'; Kind = K.Initializer; break;
    case 'C':
      Args = 'TypeAndMaybePrivateName'; Kind = K.Allocator; break;
    case 'c':
      Args = 'TypeAndMaybePrivateName'; Kind = K.Constructor; break;
    case 'U': Args = 'TypeAndIndex'; Kind = K.ExplicitClosure; break;
    case 'u': Args = 'TypeAndIndex'; Kind = K.ImplicitClosure; break;
    case 'A': Args = 'Index'; Kind = K.DefaultArgumentInitializer; break;
    case 'm': return this.demangleEntity(K.Macro);
    case 'M': return this.demangleMacroExpansion();
    case 'p': return this.demangleEntity(K.GenericTypeParamDecl);
    case 'P':
      Args = 'None';
      Kind = K.PropertyWrapperBackingInitializer;
      break;
    case 'W':
      Args = 'None';
      Kind = K.PropertyWrapperInitFromProjectedValue;
      break;
    default: return NONE;
  }

  let NameOrIndex = NONE, ParamType = NONE, LabelList = NONE,
              Context = NONE;
  switch (Args) {
    case 'None':
      break;
    case 'TypeAndMaybePrivateName':
      NameOrIndex = this.popNode(K.PrivateDeclName);
      ParamType = this.popNode(K.Type);
      LabelList = this.popFunctionParamLabels(ParamType);
      break;
    case 'TypeAndIndex':
      NameOrIndex = this.demangleIndexAsNode();
      ParamType = this.popNode(K.Type);
      break;
    case 'Index':
      NameOrIndex = this.demangleIndexAsNode();
      break;
    case 'ContextArg':
      Context = this.popNode();
      break;
  }
  let Entity = this.createWithChild(Kind, this.popContext());
  switch (Args) {
    case 'None':
      break;
    case 'Index':
      Entity = this.addChild(Entity, NameOrIndex);
      break;
    case 'TypeAndMaybePrivateName':
      this.addChild(Entity, LabelList);
      Entity = this.addChild(Entity, ParamType);
      this.addChild(Entity, NameOrIndex);
      break;
    case 'TypeAndIndex':
      Entity = this.addChild(Entity, NameOrIndex);
      Entity = this.addChild(Entity, ParamType);
      break;
    case 'ContextArg':
      Entity = this.addChild(Entity, Context);
      break;
  }
  return Entity;
}

  demangleEntity(Kind: Kind): Node {
  let Type = this.popNode(K.Type);
  let LabelList = this.popFunctionParamLabels(Type);
  let Name = this.popNode(this.isDeclName);
  let Context = this.popContext();
  let result = LabelList ? this.createWithChildren(Kind, Context, Name, LabelList, Type)
                          : this.createWithChildren(Kind, Context, Name, Type);
                          
  result = this.setParentForOpaqueReturnTypeNodes(this, result, Type);
  return result;
}

  demangleVariable(): Node {
  let Variable = this.demangleEntity(K.Variable);
  return this.demangleAccessor(Variable);
}

  demangleSubscript(): Node {
  let PrivateName = this.popNode(K.PrivateDeclName);
  let Type = this.popNode(K.Type);
  let LabelList = this.popFunctionParamLabels(Type);
  let Context = this.popContext();

  if (!Type)
    return NONE;

  let Subscript = this.createNode(K.Subscript);
  Subscript = this.addChild(Subscript, Context);
  this.addChild(Subscript, LabelList);
  Subscript = this.addChild(Subscript, Type);
  this.addChild(Subscript, PrivateName);
  
  Subscript = this.setParentForOpaqueReturnTypeNodes(this, Subscript, Type);

  return this.demangleAccessor(Subscript);
}

  demangleProtocolList(): Node {
  let TypeList = this.createNode(K.TypeList);
  let ProtoList = this.createWithChild(K.ProtocolList, TypeList);
  if (!this.popNode(K.EmptyList)) {
    let firstElem = false;
    do {
      firstElem = (this.popNode(K.FirstElementMarker) != NONE);
      let Proto = this.popProtocol();
      if (!Proto)
        return NONE;
      TypeList.addChild(Proto);
    } while (!firstElem);

    TypeList.reverseChildren();
  }
  return ProtoList;
}

  demangleProtocolListType(): Node {
  let ProtoList = this.demangleProtocolList();
  return this.createType(ProtoList);
}

  demangleConstrainedExistentialRequirementList(): Node {
  let ReqList =
      this.createNode(K.ConstrainedExistentialRequirementList);
  let firstElem = false;
  do {
    firstElem = (this.popNode(K.FirstElementMarker) != NONE);
    let Req = this.popNode(this.isRequirement);
    if (!Req)
      return NONE;
    ReqList.addChild(Req);
  } while (!firstElem);

  ReqList.reverseChildren();
  return ReqList;
}

  demangleGenericSignature(hasParamCounts: boolean): Node {
  let Sig = this.createNode(K.DependentGenericSignature);
  if (hasParamCounts) {
    while (!this.nextIf('l')) {
      let count = 0;
      if (!this.nextIf('z'))
        count = this.demangleIndex() + 1;
      if (count < 0)
        return NONE;
      Sig.addChild(this.createNode(K.DependentGenericParamCount,
                                        count));
    }
  } else {
    Sig.addChild(this.createNode(K.DependentGenericParamCount, 1));
  }
  let NumCounts = Sig.getNumChildren();
  for (let Req = this.popNode(this.isRequirement); Req; Req = this.popNode(this.isRequirement)) {
    Sig.addChild(Req);
  }
  Sig.reverseChildren(NumCounts);
  return Sig;
}

  demangleGenericRequirement(): Node {

  let TypeKind = '';
  let ConstraintKind = '';

  let inverseKind = NONE;
  switch (this.nextChar()) {
    case 'v': ConstraintKind = 'PackMarker'; TypeKind = 'Generic'; break;
    case 'c': ConstraintKind = 'BaseClass'; TypeKind = 'Assoc'; break;
    case 'C': ConstraintKind = 'BaseClass'; TypeKind = 'CompoundAssoc'; break;
    case 'b': ConstraintKind = 'BaseClass'; TypeKind = 'Generic'; break;
    case 'B': ConstraintKind = 'BaseClass'; TypeKind = 'Substitution'; break;
    case 't': ConstraintKind = 'SameType'; TypeKind = 'Assoc'; break;
    case 'T': ConstraintKind = 'SameType'; TypeKind = 'CompoundAssoc'; break;
    case 's': ConstraintKind = 'SameType'; TypeKind = 'Generic'; break;
    case 'S': ConstraintKind = 'SameType'; TypeKind = 'Substitution'; break;
    case 'm': ConstraintKind = 'Layout'; TypeKind = 'Assoc'; break;
    case 'M': ConstraintKind = 'Layout'; TypeKind = 'CompoundAssoc'; break;
    case 'l': ConstraintKind = 'Layout'; TypeKind = 'Generic'; break;
    case 'L': ConstraintKind = 'Layout'; TypeKind = 'Substitution'; break;
    case 'p': ConstraintKind = 'Protocol'; TypeKind = 'Assoc'; break;
    case 'P': ConstraintKind = 'Protocol'; TypeKind = 'CompoundAssoc'; break;
    case 'Q': ConstraintKind = 'Protocol'; TypeKind = 'Substitution'; break;
    case 'h': ConstraintKind = 'SameShape'; TypeKind = 'Generic'; break;
    case 'i': 
      ConstraintKind = 'Inverse';
      TypeKind = 'Generic';
      inverseKind = this.demangleIndexAsNode();
      if (!inverseKind)
        return NONE;
      break;
    case 'I': 
      ConstraintKind = 'Inverse';
      TypeKind = 'Substitution';
      inverseKind = this.demangleIndexAsNode();
      if (!inverseKind)
        return NONE;
      break;
    default:  ConstraintKind = 'Protocol'; TypeKind = 'Generic'; this.pushBack(); break;
  }

  let ConstrTy = NONE;

  switch (TypeKind) {
  case 'Generic':
    ConstrTy = this.createType(this.demangleGenericParamIndex());
    break;
  case 'Assoc':
    ConstrTy = this.demangleAssociatedTypeSimple(this.demangleGenericParamIndex());
    this.addSubstitution(ConstrTy);
    break;
  case 'CompoundAssoc':
    ConstrTy = this.demangleAssociatedTypeCompound(this.demangleGenericParamIndex());
    this.addSubstitution(ConstrTy);
    break;
  case 'Substitution':
    ConstrTy = this.popNode(K.Type);
    break;
  }

  switch (ConstraintKind) {
  case 'PackMarker':
    return this.createWithChild(
        K.DependentGenericParamPackMarker, ConstrTy);
  case 'Protocol':
    return this.createWithChildren(
        K.DependentGenericConformanceRequirement, ConstrTy,
        this.popProtocol());
  case 'Inverse':
    return this.createWithChildren(
        K.DependentGenericInverseConformanceRequirement,
        ConstrTy, inverseKind);
  case 'BaseClass':
    return this.createWithChildren(
        K.DependentGenericConformanceRequirement, ConstrTy,
        this.popNode(K.Type));
  case 'SameType':
    return this.createWithChildren(K.DependentGenericSameTypeRequirement,
                              ConstrTy, this.popNode(K.Type));
  case 'SameShape':
    return this.createWithChildren(K.DependentGenericSameShapeRequirement,
                              ConstrTy, this.popNode(K.Type));
  case 'Layout': {
    let c = this.nextChar();
    let size = NONE;
    let alignment = NONE;
    let name = '';
    if (c == 'U') {
      name = "U";
    } else if (c == 'R') {
      name = "R";
    } else if (c == 'N') {
      name = "N";
    } else if (c == 'C') {
      name = "C";
    } else if (c == 'D') {
      name = "D";
    } else if (c == 'T') {
      name = "T";
    } else if (c == 'B') {
      name = "B";
    } else if (c == 'E') {
      size = this.demangleIndexAsNode();
      if (!size)
        return NONE;
      alignment = this.demangleIndexAsNode();
      name = "E";
    } else if (c == 'e') {
      size = this.demangleIndexAsNode();
      if (!size)
        return NONE;
      name = "e";
    } else if (c == 'M') {
      size = this.demangleIndexAsNode();
      if (!size)
        return NONE;
      alignment = this.demangleIndexAsNode();
      name = "M";
    } else if (c == 'm') {
      size = this.demangleIndexAsNode();
      if (!size)
        return NONE;
      name = "m";
    } else if (c == 'S') {
      size = this.demangleIndexAsNode();
      if (!size)
        return NONE;
      name = "S";
    } else {
      // Unknown layout constraint.
      return NONE;
    }

    let NameNode = this.createNode(K.Identifier, name);
    let NodeKind = K.DependentGenericLayoutRequirement;
    let LayoutRequirement = this.createWithChildren(NodeKind, ConstrTy, NameNode);
    if (size)
      this.addChild(LayoutRequirement, size);
    if (alignment)
      this.addChild(LayoutRequirement, alignment);
    return LayoutRequirement;
  }
  }
  return NONE;
}

  demangleGenericType(): Node {
  let GenSig = this.popNode(K.DependentGenericSignature);
  let Ty = this.popNode(K.Type);
  return this.createType(this.createWithChildren(K.DependentGenericType,
                                       GenSig, Ty));
}

  decodeValueWitnessKind(CodeStr: string): number {
  return VALUE_WITNESSES.findIndex((v) => v[0] === CodeStr);
}

  demangleValueWitness(): Node {
  const Code = this.nextChar() + this.nextChar();
  let Kind = this.decodeValueWitnessKind(Code);
  if (Kind < 0)
    return NONE;
  let VW = this.createNode(K.ValueWitness);
  this.addChild(VW, this.createNode(K.Index, Kind));
  return this.addChild(VW, this.popNode(K.Type));
}

  isMacroExpansionNodeKind(kind: Kind): boolean {
  return kind == K.AccessorAttachedMacroExpansion ||
         kind == K.MemberAttributeAttachedMacroExpansion ||
         kind == K.FreestandingMacroExpansion ||
         kind == K.MemberAttachedMacroExpansion ||
         kind == K.PeerAttachedMacroExpansion ||
         kind == K.ConformanceAttachedMacroExpansion ||
         kind == K.ExtensionAttachedMacroExpansion ||
         kind == K.MacroExpansionLoc;
}

  demangleMacroExpansion(): Node {
  let kind: Kind;
  let isAttached: boolean;
  let isFreestanding: boolean;
  const mc = this.nextChar();
  const roles: Record<string, Kind> = { a: K.AccessorAttachedMacroExpansion, r: K.MemberAttributeAttachedMacroExpansion, m: K.MemberAttachedMacroExpansion, p: K.PeerAttachedMacroExpansion, c: K.ConformanceAttachedMacroExpansion, e: K.ExtensionAttachedMacroExpansion, q: K.PreambleAttachedMacroExpansion, b: K.BodyAttachedMacroExpansion };
  switch (mc) {
  case 'a': case 'r': case 'm': case 'p': case 'c': case 'e': case 'q': case 'b':
    kind = roles[mc]!;
    isAttached = true;
    isFreestanding = false;
    break;

  case 'f':
    kind = K.FreestandingMacroExpansion;
    isAttached = false;
    isFreestanding = true;
    break;

  case 'u':
    kind = K.MacroExpansionUniqueName;
    isAttached = false;
    isFreestanding = false;
    break;

  case 'X': {
    kind = K.MacroExpansionLoc;

    let line = this.demangleIndex();
    let col = this.demangleIndex();

    let lineNode = this.createNode(K.Index, line);
    let colNode = this.createNode(K.Index, col);

    let buffer = this.popNode(K.Identifier);
    let module = this.popNode(K.Identifier);
    return this.createWithChildren(kind, module, buffer, lineNode, colNode);
  }

  default:
    return NONE;
  }

  let macroName = this.popNode(K.Identifier);
  let privateDiscriminator = NONE;
  if (isFreestanding)
    privateDiscriminator = this.popNode(K.PrivateDeclName);
  let attachedName = NONE;
  if (isAttached)
    attachedName = this.popNode(this.isDeclName);

  let context = this.popNode(this.isMacroExpansionNodeKind);
  if (!context)
    context = this.popContext();
  let discriminator = this.demangleIndexAsNode();
  let result: Node;
  if (isAttached) {

    result = this.createWithChildren(
        kind, context, attachedName, macroName, discriminator);
  } else {
    result = this.createWithChildren(kind, context, macroName, discriminator);
  }
  if (privateDiscriminator)
    result.addChild(privateDiscriminator);
  return result;
}

}
