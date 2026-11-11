// Swift demangle tree printer (the swift-demangle default text form). Ported from
// swift/lib/Demangling/NodePrinter.cpp (swift-6.0.3-RELEASE), Copyright (c) 2014-2024 Apple Inc. and the
// Swift project authors, Apache License v2.0 with Runtime Library Exception. See README for credit.

import {
  Node, NONE, K, type Kind, FunctionSigSpecializationParamKind, VALUE_WITNESSES, STDLIB_NAME, MANGLING_MODULE_OBJC,
  LLDB_EXPRESSIONS_MODULE_NAME_PREFIX, genericParameterName,
} from './nodes.js';

/** Printing options; the defaults match swift-demangle without flags. */
export interface DemangleOptions {
  SynthesizeSugarOnTypes: boolean; QualifyEntities: boolean; DisplayExtensionContexts: boolean; DisplayUnmangledSuffix: boolean;
  DisplayModuleNames: boolean; DisplayGenericSpecializations: boolean; DisplayProtocolConformances: boolean; DisplayWhereClauses: boolean;
  DisplayEntityTypes: boolean; DisplayLocalNameContexts: boolean; ShortenPartialApply: boolean; ShortenThunk: boolean; ShortenValueWitness: boolean;
  ShortenArchetype: boolean; ShowPrivateDiscriminators: boolean; ShowFunctionArgumentTypes: boolean; DisplayDebuggerGeneratedModule: boolean;
  DisplayStdlibModule: boolean; DisplayObjCModule: boolean; PrintForTypeName: boolean; ShowAsyncResumePartial: boolean; ShowClosureSignature: boolean;
  HidingCurrentModule: string; GenericParameterName: (depth: number, index: number) => string;
}
export const DEFAULT_OPTIONS: DemangleOptions = {
  SynthesizeSugarOnTypes: true, QualifyEntities: true, DisplayExtensionContexts: true, DisplayUnmangledSuffix: true, DisplayModuleNames: true,
  DisplayGenericSpecializations: true, DisplayProtocolConformances: true, DisplayWhereClauses: true, DisplayEntityTypes: true,
  DisplayLocalNameContexts: true, ShortenPartialApply: false, ShortenThunk: false, ShortenValueWitness: false, ShortenArchetype: false,
  ShowPrivateDiscriminators: true, ShowFunctionArgumentTypes: true, DisplayDebuggerGeneratedModule: true, DisplayStdlibModule: true,
  DisplayObjCModule: true, PrintForTypeName: false, ShowAsyncResumePartial: true, ShowClosureSignature: true, HidingCurrentModule: '',
  GenericParameterName: genericParameterName,
};
/** The swift-demangle -simplified option set. */
export const SIMPLIFIED_OPTIONS: DemangleOptions = {
  ...DEFAULT_OPTIONS, SynthesizeSugarOnTypes: true, DisplayExtensionContexts: false, DisplayUnmangledSuffix: false, DisplayModuleNames: false,
  DisplayGenericSpecializations: false, DisplayProtocolConformances: false, DisplayWhereClauses: false, DisplayEntityTypes: false,
  ShortenPartialApply: true, ShortenThunk: true, ShortenValueWitness: true, ShortenArchetype: true, ShowPrivateDiscriminators: false,
  ShowFunctionArgumentTypes: false, ShowAsyncResumePartial: false,
};

const MAX_OUTPUT = 1 << 20;
class DemanglerPrinter {
  s = '';
  p(...xs: (string | number | boolean)[]): this {
    for (const x of xs) this.s += typeof x === 'boolean' ? (x ? '1' : '0') : String(x);
    if (this.s.length > MAX_OUTPUT) throw new Error('demangled output too large');
    return this;
  }
  str(): string { return this.s; }
  writeHex(n: number): this { this.s += n.toString(16).toUpperCase(); return this; }
}

function QuotedString(v: string): string {
  let o = '"';
  for (const C of v) {
    switch (C) {
    case '\\': o += '\\\\'; break;
    case '\t': o += '\\t'; break;
    case '\n': o += '\\n'; break;
    case '\r': o += '\\r'; break;
    case '"': o += '\\"'; break;
    case '\0': o += '\\0'; break;
    default: {
      const c = C.charCodeAt(0);
      if (c < 0x20 || c >= 0x7f) {
        // the C++ escapes each UTF-8 byte
        for (const b of new TextEncoder().encode(C)) o += '\\x' + '0123456789ABCDEF'[b >> 4] + '0123456789ABCDEF'[b & 15];
      } else o += C;
    }
    }
  }
  return o + '"';
}

function toStringDirectness(d: number): string { return d === 0 ? 'direct' : 'indirect'; }
function toStringValueWitness(k: number): string { const n = VALUE_WITNESSES[k]?.[1] ?? 'unknown'; return n[0]!.toLowerCase() + n.slice(1); }

enum SugarType { None, Optional, ImplicitlyUnwrappedOptional, Array, Dictionary }
enum TypePrinting { NoType, WithColon, FunctionStyle }

export class NodePrinter {
  Printer = new DemanglerPrinter();
  SpecializationPrefixPrinted = false;
  isValid = true;
  static readonly MaxDepth = 768;
  static demangleSymbolAsString: (s: string) => string = (s) => s;
  constructor(public Options: DemangleOptions = DEFAULT_OPTIONS) {}

  printRoot(root: Node): string {
  this.isValid = true;
  this.print(root, 0);
  if (this.isValid)
    return this.Printer.str();
  return "";
}


  setInvalid(): void { this.isValid = false; }

  printChildren(Node: Node | Node[], depth: number, sep: string = ''): void {
    if (!Node) return;
    const cs = Array.isArray(Node) ? Node : Node.children;
    for (let i = 0; i < cs.length; i++) {
      this.print(cs[i]!, depth + 1);
      if (sep && i + 1 < cs.length) this.Printer.p(sep);
    }
  }

  getFirstChildOfKind(Node: Node, kind: Kind): Node {
  if (!Node)
    return NONE;
  for (const child of Node.children) {
    if (child && child.getKind() == kind)
      return child;
  }
  return NONE;
}

  printBoundGenericNoSugar(Node: Node, depth: number): void {
  if (Node.getNumChildren() < 2)
    return;
  let typelist = Node.getChild(1);
  this.print(Node.getChild(0), depth + 1);
  this.Printer.p("<");
  this.printChildren(typelist, depth, ", ");
  this.Printer.p(">");
}

  printOptionalIndex(node: Node): void {
  /* assert */ void 0;
  if (node.hasIndex())
    this.Printer.p("#", node.getIndex(), " ");
}

  isSwiftModule(node: Node): boolean {
  return (node.getKind() == K.Module &&
          node.getText() == STDLIB_NAME);
}

  printContext(Context: Node): boolean {
  if (!this.Options.QualifyEntities)
    return false;

  if (Context.getKind() == K.Module) {
    if (Context.getText() == STDLIB_NAME)
      return this.Options.DisplayStdlibModule;
    if (Context.getText() == MANGLING_MODULE_OBJC)
      return this.Options.DisplayObjCModule;
    if (Context.getText() == this.Options.HidingCurrentModule)
      return false;
    if (Context.getText().startsWith(LLDB_EXPRESSIONS_MODULE_NAME_PREFIX))
      return this.Options.DisplayDebuggerGeneratedModule;
  }
  return true;
}

  isIdentifier(node: Node, desired: string): boolean {
  return (node.getKind() == K.Identifier &&
          node.getText() == desired);
}


  isSimpleType(Node: Node): boolean {
  switch (Node.getKind()) {
  case K.AssociatedType:
  case K.AssociatedTypeRef:
  case K.BoundGenericClass:
  case K.BoundGenericEnum:
  case K.BoundGenericStructure:
  case K.BoundGenericProtocol:
  case K.BoundGenericOtherNominalType:
  case K.BoundGenericTypeAlias:
  case K.BoundGenericFunction:
  case K.BuiltinTypeName:
  case K.BuiltinTupleType:
  case K.Class:
  case K.DependentGenericType:
  case K.DependentMemberType:
  case K.DependentGenericParamType:
  case K.DynamicSelf:
  case K.Enum:
  case K.ErrorType:
  case K.ExistentialMetatype:
  case K.Metatype:
  case K.MetatypeRepresentation:
  case K.Module:
  case K.Tuple:
  case K.Pack:
  case K.SILPackDirect:
  case K.SILPackIndirect:
  case K.ConstrainedExistentialRequirementList:
  case K.ConstrainedExistentialSelf:
  case K.Protocol:
  case K.ProtocolSymbolicReference:
  case K.ReturnType:
  case K.SILBoxType:
  case K.SILBoxTypeWithLayout:
  case K.Structure:
  case K.OtherNominalType:
  case K.TupleElementName:
  case K.TypeAlias:
  case K.TypeList:
  case K.LabelList:
  case K.TypeSymbolicReference:
  case K.SugaredOptional:
  case K.SugaredArray:
  case K.SugaredDictionary:
  case K.SugaredParen:
    return true;

  case K.Type:
    return this.isSimpleType(Node.getChild(0));

  case K.ProtocolList:
    return Node.getChild(0).getNumChildren() <= 1;

  case K.ProtocolListWithAnyObject:
    return Node.getChild(0).getChild(0).getNumChildren() == 0;

  case K.ConstrainedExistential:
  case K.PackElement:
  case K.PackElementLevel:
  case K.PackExpansion:
  case K.ProtocolListWithClass:
  case K.AccessorAttachedMacroExpansion:
  case K.AccessorFunctionReference:
  case K.Allocator:
  case K.ArgumentTuple:
  case K.AssociatedConformanceDescriptor:
  case K.AssociatedTypeDescriptor:
  case K.AssociatedTypeMetadataAccessor:
  case K.AssociatedTypeWitnessTableAccessor:
  case K.AsyncRemoved:
  case K.AutoClosureType:
  case K.BaseConformanceDescriptor:
  case K.BaseWitnessTableAccessor:
  case K.BodyAttachedMacroExpansion:
  case K.ClangType:
  case K.ClassMetadataBaseOffset:
  case K.CFunctionPointer:
  case K.ConformanceAttachedMacroExpansion:
  case K.Constructor:
  case K.CoroutineContinuationPrototype:
  case K.CurryThunk:
  case K.DispatchThunk:
  case K.Deallocator:
  case K.DeclContext:
  case K.DefaultArgumentInitializer:
  case K.DefaultAssociatedTypeMetadataAccessor:
  case K.DefaultAssociatedConformanceAccessor:
  case K.DependentAssociatedTypeRef:
  case K.DependentGenericSignature:
  case K.DependentGenericParamPackMarker:
  case K.DependentGenericParamCount:
  case K.DependentGenericConformanceRequirement:
  case K.DependentGenericLayoutRequirement:
  case K.DependentGenericSameTypeRequirement:
  case K.DependentGenericSameShapeRequirement:
  case K.DependentPseudogenericSignature:
  case K.Destructor:
  case K.DidSet:
  case K.DirectMethodReferenceAttribute:
  case K.Directness:
  case K.DynamicAttribute:
  case K.EscapingAutoClosureType:
  case K.EscapingObjCBlock:
  case K.NoEscapeFunctionType:
  case K.ExplicitClosure:
  case K.Extension:
  case K.ExtensionAttachedMacroExpansion:
  case K.EnumCase:
  case K.FieldOffset:
  case K.FreestandingMacroExpansion:
  case K.FullObjCResilientClassStub:
  case K.FullTypeMetadata:
  case K.Function:
  case K.FunctionSignatureSpecialization:
  case K.FunctionSignatureSpecializationParam:
  case K.FunctionSignatureSpecializationReturn:
  case K.FunctionSignatureSpecializationParamKind:
  case K.FunctionSignatureSpecializationParamPayload:
  case K.FunctionType:
  case K.GenericProtocolWitnessTable:
  case K.GenericProtocolWitnessTableInstantiationFunction:
  case K.GenericPartialSpecialization:
  case K.GenericPartialSpecializationNotReAbstracted:
  case K.GenericSpecialization:
  case K.GenericSpecializationNotReAbstracted:
  case K.GenericSpecializationInResilienceDomain:
  case K.GenericSpecializationParam:
  case K.GenericSpecializationPrespecialized:
  case K.InlinedGenericFunction:
  case K.GenericTypeMetadataPattern:
  case K.Getter:
  case K.Global:
  case K.GlobalGetter:
  case K.Identifier:
  case K.Index:
  case K.InitAccessor:
  case K.IVarInitializer:
  case K.IVarDestroyer:
  case K.ImplDifferentiabilityKind:
  case K.ImplEscaping:
  case K.ImplErasedIsolation:
  case K.ImplSendingResult:
  case K.ImplConvention:
  case K.ImplParameterResultDifferentiability:
  case K.ImplParameterSending:
  case K.ImplFunctionAttribute:
  case K.ImplFunctionConvention:
  case K.ImplFunctionConventionName:
  case K.ImplFunctionType:
  case K.ImplInvocationSubstitutions:
  case K.ImplPatternSubstitutions:
  case K.ImplicitClosure:
  case K.ImplParameter:
  case K.ImplResult:
  case K.ImplYield:
  case K.ImplErrorResult:
  case K.InOut:
  case K.InfixOperator:
  case K.Initializer:
  case K.Isolated:
  case K.Sending:
  case K.CompileTimeConst:
  case K.PropertyWrapperBackingInitializer:
  case K.PropertyWrapperInitFromProjectedValue:
  case K.KeyPathGetterThunkHelper:
  case K.KeyPathSetterThunkHelper:
  case K.KeyPathEqualsThunkHelper:
  case K.KeyPathHashThunkHelper:
  case K.LazyProtocolWitnessTableAccessor:
  case K.LazyProtocolWitnessTableCacheVariable:
  case K.LocalDeclName:
  case K.Macro:
  case K.MacroExpansionLoc:
  case K.MacroExpansionUniqueName:
  case K.MaterializeForSet:
  case K.MemberAttributeAttachedMacroExpansion:
  case K.MemberAttachedMacroExpansion:
  case K.MergedFunction:
  case K.Metaclass:
  case K.MethodDescriptor:
  case K.MethodLookupFunction:
  case K.ModifyAccessor:
  case K.NativeOwningAddressor:
  case K.NativeOwningMutableAddressor:
  case K.NativePinningAddressor:
  case K.NativePinningMutableAddressor:
  case K.NominalTypeDescriptor:
  case K.NominalTypeDescriptorRecord:
  case K.NonObjCAttribute:
  case K.Number:
  case K.ObjCAsyncCompletionHandlerImpl:
  case K.ObjCAttribute:
  case K.ObjCBlock:
  case K.ObjCMetadataUpdateFunction:
  case K.ObjCResilientClassStub:
  case K.OpaqueTypeDescriptor:
  case K.OpaqueTypeDescriptorRecord:
  case K.OpaqueTypeDescriptorAccessor:
  case K.OpaqueTypeDescriptorAccessorImpl:
  case K.OpaqueTypeDescriptorAccessorKey:
  case K.OpaqueTypeDescriptorAccessorVar:
  case K.Owned:
  case K.OwningAddressor:
  case K.OwningMutableAddressor:
  case K.PartialApplyForwarder:
  case K.PartialApplyObjCForwarder:
  case K.PeerAttachedMacroExpansion:
  case K.PostfixOperator:
  case K.PreambleAttachedMacroExpansion:
  case K.PredefinedObjCAsyncCompletionHandlerImpl:
  case K.PrefixOperator:
  case K.PrivateDeclName:
  case K.PropertyDescriptor:
  case K.ProtocolConformance:
  case K.ProtocolConformanceDescriptor:
  case K.ProtocolConformanceDescriptorRecord:
  case K.MetadataInstantiationCache:
  case K.ProtocolDescriptor:
  case K.ProtocolDescriptorRecord:
  case K.ProtocolRequirementsBaseDescriptor:
  case K.ProtocolSelfConformanceDescriptor:
  case K.ProtocolSelfConformanceWitness:
  case K.ProtocolSelfConformanceWitnessTable:
  case K.ProtocolWitness:
  case K.ProtocolWitnessTable:
  case K.ProtocolWitnessTableAccessor:
  case K.ProtocolWitnessTablePattern:
  case K.ReabstractionThunk:
  case K.ReabstractionThunkHelper:
  case K.ReabstractionThunkHelperWithSelf:
  case K.ReabstractionThunkHelperWithGlobalActor:
  case K.ReadAccessor:
  case K.RelatedEntityDeclName:
  case K.RetroactiveConformance:
  case K.Setter:
  case K.Shared:
  case K.SILBoxLayout:
  case K.SILBoxMutableField:
  case K.SILBoxImmutableField:
  case K.IsSerialized:
  case K.MetatypeParamsRemoved:
  case K.SpecializationPassID:
  case K.Static:
  case K.Subscript:
  case K.Suffix:
  case K.ThinFunctionType:
  case K.TupleElement:
  case K.TypeMangling:
  case K.TypeMetadata:
  case K.TypeMetadataAccessFunction:
  case K.TypeMetadataCompletionFunction:
  case K.TypeMetadataInstantiationCache:
  case K.TypeMetadataInstantiationFunction:
  case K.TypeMetadataSingletonInitializationCache:
  case K.TypeMetadataDemanglingCache:
  case K.TypeMetadataLazyCache:
  case K.UncurriedFunctionType:
  case K.Weak: case K.Unowned: case K.Unmanaged:
  case K.UnknownIndex:
  case K.UnsafeAddressor:
  case K.UnsafeMutableAddressor:
  case K.ValueWitness:
  case K.ValueWitnessTable:
  case K.Variable:
  case K.VTableAttribute:
  case K.VTableThunk:
  case K.WillSet:
  case K.ReflectionMetadataBuiltinDescriptor:
  case K.ReflectionMetadataFieldDescriptor:
  case K.ReflectionMetadataAssocTypeDescriptor:
  case K.ReflectionMetadataSuperclassDescriptor:
  case K.ResilientProtocolWitnessTable:
  case K.GenericTypeParamDecl:
  case K.ConcurrentFunctionType:
  case K.DifferentiableFunctionType:
  case K.GlobalActorFunctionType:
  case K.IsolatedAnyFunctionType:
  case K.SendingResultFunctionType:
  case K.AsyncAnnotation:
  case K.ThrowsAnnotation:
  case K.TypedThrowsAnnotation:
  case K.EmptyList:
  case K.FirstElementMarker:
  case K.VariadicMarker:
  case K.OutlinedBridgedMethod:
  case K.OutlinedCopy:
  case K.OutlinedConsume:
  case K.OutlinedRetain:
  case K.OutlinedRelease:
  case K.OutlinedInitializeWithTake:
  case K.OutlinedInitializeWithCopy:
  case K.OutlinedAssignWithTake:
  case K.OutlinedAssignWithCopy:
  case K.OutlinedDestroy:
  case K.OutlinedInitializeWithCopyNoValueWitness:
  case K.OutlinedAssignWithTakeNoValueWitness:
  case K.OutlinedAssignWithCopyNoValueWitness:
  case K.OutlinedDestroyNoValueWitness:
  case K.OutlinedEnumTagStore:
  case K.OutlinedEnumGetTag:
  case K.OutlinedEnumProjectDataForLoad:
  case K.OutlinedVariable:
  case K.OutlinedReadOnlyObject:
  case K.AssocTypePath:
  case K.ModuleDescriptor:
  case K.AnonymousDescriptor:
  case K.AssociatedTypeGenericParamRef:
  case K.ExtensionDescriptor:
  case K.AnonymousContext:
  case K.AnyProtocolConformanceList:
  case K.ConcreteProtocolConformance:
  case K.PackProtocolConformance:
  case K.DependentAssociatedConformance:
  case K.DependentProtocolConformanceAssociated:
  case K.DependentProtocolConformanceInherited:
  case K.DependentProtocolConformanceRoot:
  case K.ProtocolConformanceRefInTypeModule:
  case K.ProtocolConformanceRefInProtocolModule:
  case K.ProtocolConformanceRefInOtherModule:
  case K.DistributedThunk:
  case K.DistributedAccessor:
  case K.DynamicallyReplaceableFunctionKey:
  case K.DynamicallyReplaceableFunctionImpl:
  case K.DynamicallyReplaceableFunctionVar:
  case K.OpaqueType:
  case K.OpaqueTypeDescriptorSymbolicReference:
  case K.OpaqueReturnType:
  case K.OpaqueReturnTypeIndex:
  case K.OpaqueReturnTypeParent:
  case K.OpaqueReturnTypeOf:
  case K.CanonicalSpecializedGenericMetaclass:
  case K.CanonicalSpecializedGenericTypeMetadataAccessFunction:
  case K.NoncanonicalSpecializedGenericTypeMetadata:
  case K.NoncanonicalSpecializedGenericTypeMetadataCache:
  case K.GlobalVariableOnceDeclList:
  case K.GlobalVariableOnceFunction:
  case K.GlobalVariableOnceToken:
  case K.CanonicalPrespecializedGenericTypeCachingOnceToken:
  case K.AsyncFunctionPointer:
  case K.AutoDiffFunction:
  case K.AutoDiffDerivativeVTableThunk:
  case K.AutoDiffSelfReorderingReabstractionThunk:
  case K.AutoDiffSubsetParametersThunk:
  case K.AutoDiffFunctionKind:
  case K.DifferentiabilityWitness:
  case K.NoDerivative:
  case K.IndexSubset:
  case K.AsyncAwaitResumePartialFunction:
  case K.AsyncSuspendResumePartialFunction:
  case K.AccessibleFunctionRecord:
  case K.BackDeploymentThunk:
  case K.BackDeploymentFallback:
  case K.ExtendedExistentialTypeShape:
  case K.Uniquable:
  case K.UniqueExtendedExistentialTypeShapeSymbolicReference:
  case K.NonUniqueExtendedExistentialTypeShapeSymbolicReference:
  case K.SymbolicExtendedExistentialType:
  case K.HasSymbolQuery:
  case K.ObjectiveCProtocolSymbolicReference:
  case K.ParamLifetimeDependence:
  case K.SelfLifetimeDependence:
  case K.DependentGenericInverseConformanceRequirement:
    return false;
  }
  throw new Error("bad node kind");
}

  printWithParens(type: Node, depth: number): void {
  let needs_parens = !this.isSimpleType(type);
  if (needs_parens)
    this.Printer.p("(");
  this.print(type, depth + 1);
  if (needs_parens)
    this.Printer.p(")");
}

  findSugar(Node: Node): SugarType {
  if (Node.getNumChildren() == 1 &&
      Node.getKind() == K.Type)
    return this.findSugar(Node.getChild(0));
  
  if (Node.getNumChildren() != 2)
    return SugarType.None;
  
  if (Node.getKind() != K.BoundGenericEnum &&
      Node.getKind() != K.BoundGenericStructure)
    return SugarType.None;

  let unboundType = Node.getChild(0).getChild(0); // drill through Type
  let typeArgs = Node.getChild(1);
  
  if (Node.getKind() == K.BoundGenericEnum) {
    // Swift.Optional
    if (this.isIdentifier(unboundType.getChild(1), "Optional") &&
        typeArgs.getNumChildren() == 1 &&
        this.isSwiftModule(unboundType.getChild(0))) {
      return SugarType.Optional;
    }

    // Swift.ImplicitlyUnwrappedOptional
    if (this.isIdentifier(unboundType.getChild(1), 
                     "ImplicitlyUnwrappedOptional") &&
        typeArgs.getNumChildren() == 1 &&
        this.isSwiftModule(unboundType.getChild(0))) {
      return SugarType.ImplicitlyUnwrappedOptional;
    }

    return SugarType.None;
  }

  /* assert */ void 0;

  // Array
  if (this.isIdentifier(unboundType.getChild(1), "Array") &&
      typeArgs.getNumChildren() == 1 &&
      this.isSwiftModule(unboundType.getChild(0))) {
    return SugarType.Array;
  }

  // Dictionary
  if (this.isIdentifier(unboundType.getChild(1), "Dictionary") &&
      typeArgs.getNumChildren() == 2 &&
      this.isSwiftModule(unboundType.getChild(0))) {
    return SugarType.Dictionary;
  }

  return SugarType.None;
}

  printBoundGeneric(Node: Node, depth: number): void {
  if (Node.getNumChildren() < 2)
    return;
  if (Node.getNumChildren() != 2) {
    this.printBoundGenericNoSugar(Node, depth);
    return;
  }

  if (!this.Options.SynthesizeSugarOnTypes ||
      Node.getKind() == K.BoundGenericClass)
  {
    // no sugar here
    this.printBoundGenericNoSugar(Node, depth);
    return;
  }

  // Print the conforming type for a "bound" protocol node "as" the protocol
  // type.
  if (Node.getKind() == K.BoundGenericProtocol) {
    this.printChildren(Node.getChild(1), depth);
    this.Printer.p(" as ");
    this.print(Node.getChild(0), depth + 1);
    return;
  }

  let sugarType = this.findSugar(Node);
  
  switch (sugarType) {
    case SugarType.None:
      this.printBoundGenericNoSugar(Node, depth);
      break;
    case SugarType.Optional:
    case SugarType.ImplicitlyUnwrappedOptional: {
      let type = Node.getChild(1).getChild(0);
      this.printWithParens(type, depth);
      this.Printer.p((sugarType == SugarType.Optional ? "?" : "!"));
      break;
    }
    case SugarType.Array: {
      let type = Node.getChild(1).getChild(0);
      this.Printer.p("[");
      this.print(type, depth + 1);
      this.Printer.p("]");
      break;
    }
    case SugarType.Dictionary: {
      let keyType = Node.getChild(1).getChild(0);
      let valueType = Node.getChild(1).getChild(1);
      this.Printer.p("[");
      this.print(keyType, depth + 1);
      this.Printer.p(" : ");
      this.print(valueType, depth + 1);
      this.Printer.p("]");
      break;
    }
  }
}

  getChildIf(Node: Node, Kind: Kind): Node {
  return Node.children.find((child) => child.getKind() == Kind) ?? NONE;
}

  printFunctionParameters(LabelList: Node, ParameterType: Node, depth: number, showTypes: boolean): void {
  if (ParameterType.getKind() != K.ArgumentTuple) {
    this.setInvalid();
    return;
  }

  let Parameters = ParameterType.getFirstChild();
  /* assert */ void 0;
  Parameters = Parameters.getFirstChild();
  if (Parameters.getKind() != K.Tuple) {
    // only a single not-named parameter
    if (showTypes) {
      this.Printer.p('(');
      this.print(Parameters, depth + 1);
      this.Printer.p(')');
    } else {
      this.Printer.p("(_:)");
    }
    return;
  }

  let getLabelFor = (_Param: Node, Index: number): string => {
    let Label = LabelList.getChild(Index);
    /* assert */ void 0;
    return Label.getKind() == K.Identifier ? Label.getText()
                                                      : "_";
  };

  let ParamIndex = 0;
  let hasLabels = LabelList && LabelList.getNumChildren() > 0;

  this.Printer.p('(');
  Parameters.children.forEach((Param, pi) => {
        if (pi > 0) this.Printer.p((showTypes ? ", " : ""));
        /* assert */ void 0;

        if (hasLabels) {
          this.Printer.p(getLabelFor(Param, ParamIndex), ':');
        } else if (!showTypes) {
          const Label = this.getChildIf(Param, K.TupleElementName);
          if (Label)
            this.Printer.p(Label.getText(), ":");
          else
            this.Printer.p("_:");
        }

        if (hasLabels && showTypes)
          this.Printer.p(' ');

        ++ParamIndex;

        if (showTypes)
          this.print(Param, depth + 1);
      });
  this.Printer.p(')');
}

  printFunctionType(LabelList: Node, node: Node, depth: number): void {
  if (node.getNumChildren() < 2) {
    this.setInvalid();
    return;
  }

  let printConventionWithMangledCType = (convention: string) => {
    this.Printer.p("@convention(", convention);
    if (node.getFirstChild().getKind() == K.ClangType) {
      this.Printer.p(", mangledCType: \"");
      this.print(node.getFirstChild(), depth + 1);
      this.Printer.p('"');
    }
    this.Printer.p(") ");
  };

  switch (node.getKind()) {
  case K.FunctionType:
  case K.UncurriedFunctionType:
  case K.NoEscapeFunctionType:
    break;
  case K.AutoClosureType:
  case K.EscapingAutoClosureType:
    this.Printer.p("@autoclosure "); break;
  case K.ThinFunctionType:
    this.Printer.p("@convention(thin) "); break;
  case K.CFunctionPointer:
    printConventionWithMangledCType("c");
    break;
  case K.EscapingObjCBlock:
    this.Printer.p("@escaping ");
    printConventionWithMangledCType("block");
    break;
  case K.ObjCBlock:
    printConventionWithMangledCType("block");
    break;
  default:
    /* assert */ void 0;
  }

  let argIndex = node.getNumChildren() - 2;
  let startIndex = 0;
  let isSendable = false, isAsync = false, hasSendingResult = false;
  let diffKind = '\0';
  if (node.getChild(startIndex).getKind() == K.ClangType) {
    // handled earlier
    ++startIndex;
  }
  if (node.getChild(startIndex).getKind()
          == K.IsolatedAnyFunctionType) {
    this.print(node.getChild(startIndex), depth + 1);
    ++startIndex;
  }
  if (node.getChild(startIndex).getKind() ==
        K.GlobalActorFunctionType) {
    this.print(node.getChild(startIndex), depth + 1);
    ++startIndex;
  }
  if (node.getChild(startIndex).getKind() ==
      K.DifferentiableFunctionType) {
    diffKind = String.fromCharCode(node.getChild(startIndex).getIndex());
    ++startIndex;
  }
  if (node.getChild(startIndex).getKind() ==
      K.SelfLifetimeDependence) {
    this.print(node.getChild(startIndex), depth + 1);
    ++startIndex;
  }

  let thrownErrorNode = NONE;
  if (node.getChild(startIndex).getKind() == K.ThrowsAnnotation ||
      node.getChild(startIndex).getKind()
        == K.TypedThrowsAnnotation) {
    thrownErrorNode = node.getChild(startIndex);
    ++startIndex;
  }

  if (node.getChild(startIndex).getKind()
          == K.ConcurrentFunctionType) {
    ++startIndex;
    isSendable = true;
  }
  if (node.getChild(startIndex).getKind() == K.AsyncAnnotation) {
    ++startIndex;
    isAsync = true;
  }
  if (node.getChild(startIndex).getKind() ==
      K.SendingResultFunctionType) {
    ++startIndex;
    hasSendingResult = true;
  }

  switch (diffKind) {
  case 'f':
    this.Printer.p("@differentiable(_forward) ");
    break;
  case 'r':
    this.Printer.p("@differentiable(reverse) ");
    break;
  case 'l':
    this.Printer.p("@differentiable(_linear) ");
    break;
  case 'd':
    this.Printer.p("@differentiable ");
    break;
  default:
    break;
  }

  if (isSendable)
    this.Printer.p("@Sendable ");

  this.printFunctionParameters(LabelList, node.getChild(argIndex), depth,
                          this.Options.ShowFunctionArgumentTypes);

  if (!this.Options.ShowFunctionArgumentTypes)
    return;

  if (isAsync)
    this.Printer.p(" async");

  if (thrownErrorNode) {
    this.print(thrownErrorNode, depth + 1);
  }

  this.Printer.p(" -> ");

  if (hasSendingResult)
    this.Printer.p("sending ");

  this.print(node.getChild(argIndex + 1), depth + 1);
}

  printImplFunctionType(fn: Node, depth: number): void {
  let patternSubs = NONE;
  let invocationSubs = NONE;
  let sendingResult = NONE;
  const Attrs = 0, Inputs = 1, Results = 2;
  let curState = Attrs;
  let transitionTo = (newState: number) => {
    for (; curState < newState; curState = curState + 1) {
      switch (curState) {
      case Attrs:
        if (patternSubs) {
          this.Printer.p("@substituted ");
          this.print(patternSubs.getChild(0), depth + 1);
          this.Printer.p(' ');
        }
        this.Printer.p('(');
        continue;
      case Inputs:
        this.Printer.p(") -> ");
        if (sendingResult) {
          this.print(sendingResult, depth + 1);
          this.Printer.p(" ");
        }
        this.Printer.p("(");
        continue;
      default: return;
      }
    }
  };

  for (const child of fn.children) {
    if (child.getKind() == K.ImplParameter) {
      if (curState == Inputs) this.Printer.p(", ");
      transitionTo(Inputs);
      this.print(child, depth + 1);
    } else if (child.getKind() == K.ImplResult
               || child.getKind() == K.ImplYield
               || child.getKind() == K.ImplErrorResult) {
      if (curState == Results) this.Printer.p(", ");
      transitionTo(Results);
      this.print(child, depth + 1);
    } else if (child.getKind() == K.ImplPatternSubstitutions) {
      patternSubs = child;
    } else if (child.getKind() == K.ImplInvocationSubstitutions) {
      invocationSubs = child;
    } else if (child.getKind() == K.ImplSendingResult) {
      sendingResult = child;
    } else {
      /* assert */ void 0;
      this.print(child, depth + 1);
      this.Printer.p(' ');
    }
  }
  transitionTo(Results);
  this.Printer.p(')');

  if (patternSubs) {
    this.Printer.p(" for <");
    this.printChildren(patternSubs.getChild(1), depth);
    this.Printer.p('>');
  }
  if (invocationSubs) {
    this.Printer.p(" for <");
    this.printChildren(invocationSubs.getChild(0), depth);
    this.Printer.p('>');
  }
}

  printGenericSignature(Node: Node, depth: number): void {
  this.Printer.p('<');

  let numChildren = Node.getNumChildren();

  let numGenericParams = 0;
  for (; numGenericParams < numChildren; ++numGenericParams) {
    if (Node.getChild(numGenericParams).getKind()
             != K.DependentGenericParamCount) {
      break;
    }
  }

  let firstRequirement = numGenericParams;
  for (; firstRequirement < numChildren; ++firstRequirement) {
    let child = Node.getChild(firstRequirement);
    if (child.getKind() == K.Type)
      child = child.getChild(0);
    if (child.getKind() != K.DependentGenericParamPackMarker) {
      break;
    }
  }

  let isGenericParamPack = (depth: number, index: number) => {

    for (let i = numGenericParams; i < firstRequirement; ++i) {
      let child = Node.getChild(i);
      if (child.getKind() != K.DependentGenericParamPackMarker)
        continue;
      child = child.getChild(0);

      if (child.getKind() != K.Type)
        continue;

      child = child.getChild(0);
      if (child.getKind() != K.DependentGenericParamType)
        continue;

      if (index == child.getChild(0).getIndex() &&
          depth == child.getChild(1).getIndex()) {
        return true;
      }
    }

    return false;
  };

  let gpDepth = 0;
  for (; gpDepth < numGenericParams; ++gpDepth) {
    if (gpDepth != 0)
      this.Printer.p("><");

    let count = Node.getChild(gpDepth).getIndex();
    for (let index = 0; index < count; ++index) {
      if (index != 0)
        this.Printer.p(", ");

      // Limit the number of printed generic parameters. In practice this
      // it will never be exceeded. The limit is only important for malformed
      // symbols where count can be really huge.
      if (index >= 128) {
        this.Printer.p("...");
        break;
      }

      if (isGenericParamPack(gpDepth, index))
        this.Printer.p("each ");

      // FIXME: Depth won't match when a generic signature applies to a
      // method in generic type context.
      this.Printer.p(this.Options.GenericParameterName(gpDepth, index));
    }
  }

  if (firstRequirement != numChildren) {
    if (this.Options.DisplayWhereClauses) {
      this.Printer.p(" where ");
      for (let i = firstRequirement; i < numChildren; ++i) {
        if (i > firstRequirement)
          this.Printer.p(", ");
        this.print(Node.getChild(i), depth + 1);
      }
    }
  }
  this.Printer.p('>');
}


  isExistentialType(node: Node): boolean {
  return (node.getKind() == K.ExistentialMetatype ||
          node.getKind() == K.ProtocolList ||
          node.getKind() == K.ProtocolListWithClass ||
          node.getKind() == K.ProtocolListWithAnyObject);
}


  printFunctionSigSpecializationParams(Node: Node, depth: number): void {
  let Idx = 0;
  let End = Node.getNumChildren();
  while (Idx < End) {
    let firstChild = Node.getChild(Idx);
    let V = firstChild.getIndex();
    let PK = V as FunctionSigSpecializationParamKind;
    switch (PK) {
    case FunctionSigSpecializationParamKind.BoxToValue:
    case FunctionSigSpecializationParamKind.BoxToStack:
    case FunctionSigSpecializationParamKind.InOutToOut:
      this.print(Node.getChild(Idx++), depth + 1);
      break;
    case FunctionSigSpecializationParamKind.ConstantPropFunction:
    case FunctionSigSpecializationParamKind.ConstantPropGlobal: {
      this.Printer.p("[");
      this.print(Node.getChild(Idx++), depth + 1);
      this.Printer.p(" : ");
      const text = Node.getChild(Idx++).getText();
      let demangledName = NodePrinter.demangleSymbolAsString(text);
      if (demangledName.length === 0) {
        this.Printer.p(text);
      } else {
        this.Printer.p(demangledName);
      }
      this.Printer.p("]");
      break;
    }
    case FunctionSigSpecializationParamKind.ConstantPropInteger:
    case FunctionSigSpecializationParamKind.ConstantPropFloat:
      this.Printer.p("[");
      this.print(Node.getChild(Idx++), depth + 1);
      this.Printer.p(" : ");
      this.print(Node.getChild(Idx++), depth + 1);
      this.Printer.p("]");
      break;
    case FunctionSigSpecializationParamKind.ConstantPropString:
      this.Printer.p("[");
      this.print(Node.getChild(Idx++), depth + 1);
      this.Printer.p(" : ");
      this.print(Node.getChild(Idx++), depth + 1);
      this.Printer.p("'");
      this.print(Node.getChild(Idx++), depth + 1);
      this.Printer.p("'");
      this.Printer.p("]");
      break;
    case FunctionSigSpecializationParamKind.ConstantPropKeyPath:
      this.Printer.p("[");
      this.print(Node.getChild(Idx++), depth + 1);
      this.Printer.p(" : ");
      this.print(Node.getChild(Idx++), depth + 1);
      this.Printer.p("<");
      this.print(Node.getChild(Idx++), depth + 1);
      this.Printer.p(",");
      this.print(Node.getChild(Idx++), depth + 1);
      this.Printer.p(">]");
      break;
    case FunctionSigSpecializationParamKind.ClosureProp:
      this.Printer.p("[");
      this.print(Node.getChild(Idx++), depth + 1);
      this.Printer.p(" : ");
      this.print(Node.getChild(Idx++), depth + 1);
      this.Printer.p(", Argument Types : [");
      for (let e = Node.getNumChildren(); Idx < e;) {
        let child = Node.getChild(Idx);
        // Until we no longer have a type node, keep demangling.
        if (child.getKind() != K.Type)
          break;
        this.print(child, depth + 1);
        ++Idx;

        // If we are not done, this.print the ", ".
        if (Idx < e && Node.getChild(Idx).hasText())
          this.Printer.p(", ");
      }
      this.Printer.p("]");
      break;
    default:
      /* assert */ void 0;
      this.print(Node.getChild(Idx++), depth + 1);
    }
  }
}

  printSpecializationPrefix(node: Node, Description: string, depth: number, ParamPrefix: string = ''): void {
  if (!this.Options.DisplayGenericSpecializations) {
    if (!this.SpecializationPrefixPrinted) {
      this.Printer.p("specialized ");
      this.SpecializationPrefixPrinted = true;
    }
    return;
  }
  this.Printer.p(Description, " <");
  let Separator = "";
  let argNum = 0;
  for (const child of node.children) {
    switch (child.getKind()) {
      case K.SpecializationPassID:
      case K.MetatypeParamsRemoved:
        // We skip those nodes since it does not contain any
        // information that is useful to our users.
        break;

      case K.IsSerialized:
        this.Printer.p(Separator);
        Separator = ", ";
        this.print(child, depth + 1);
        break;

      default:
        // Ignore empty specializations.
        if (child.hasChildren()) {
          this.Printer.p(Separator, ParamPrefix);
          Separator = ", ";
          switch (child.getKind()) {
          case K.FunctionSignatureSpecializationParam:
            this.Printer.p("Arg[", argNum, "] = ");
            this.printFunctionSigSpecializationParams(child, depth);
            break;
          case K.FunctionSignatureSpecializationReturn:
            this.Printer.p("Return = ");
            this.printFunctionSigSpecializationParams(child, depth);
            break;
          default:
            this.print(child, depth + 1);
          }
        }
        ++argNum;
        break;
    }
  }
  this.Printer.p("> of ");
}

  isClassType(Node: Node): boolean {
  return Node.getKind() == K.Class;
}

  needSpaceBeforeType(Type: Node): boolean {
  switch (Type.getKind()) {
    case K.Type:
      return this.needSpaceBeforeType(Type.getFirstChild());
    case K.FunctionType:
    case K.NoEscapeFunctionType:
    case K.UncurriedFunctionType:
    case K.DependentGenericType:
      return false;
    default:
      return true;
  }
}


  shouldShowEntityType(EntityKind: Kind, _Options: DemangleOptions): boolean {
  switch (EntityKind) {
  case K.ExplicitClosure:
  case K.ImplicitClosure:
    // The signature of a closure (its `Type` node) can optionally be omitted.
    // Unlike functions which can have overloads, the signature of a closure is
    // not needed to be uniquely identified. A closure is uniquely identified by
    // its index and parent. Omitting the signature improves the readability
    // when long type names are in use.
    return this.Options.ShowClosureSignature;
  default:
    return true;
  }
}

  print(Node: Node, depth: number, asPrefixContext: boolean = false): Node {
  if (depth > NodePrinter.MaxDepth) {
    this.Printer.p("<<too complex>>");
    return NONE;
  }

  if (!Node) {
    this.Printer.p("<null node pointer>");
    return NONE;
  }

  const kind = Node.getKind();
  switch (kind) {

  case K.Static:
    this.Printer.p("static ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.AsyncRemoved:
    this.Printer.p("async demotion of ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.CurryThunk:
    this.Printer.p("curry thunk of ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.DispatchThunk:
    this.Printer.p("dispatch thunk of ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.MethodDescriptor:
    this.Printer.p("method descriptor for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.MethodLookupFunction:
    this.Printer.p("method lookup function for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ObjCMetadataUpdateFunction:
    this.Printer.p("ObjC metadata update function for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ObjCResilientClassStub:
    this.Printer.p("ObjC resilient class stub for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.FullObjCResilientClassStub:
    this.Printer.p("full ObjC resilient class stub for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OutlinedBridgedMethod:
    this.Printer.p("outlined bridged method (", Node.getText(), ") of ");
    return NONE;
  case K.OutlinedCopy:
    this.Printer.p("outlined copy of ");
    this.print(Node.getChild(0), depth + 1);
    if (Node.getNumChildren() > 1)
      this.print(Node.getChild(1), depth + 1);
    return NONE;
  case K.OutlinedConsume:
    this.Printer.p("outlined consume of ");
    this.print(Node.getChild(0), depth + 1);
    if (Node.getNumChildren() > 1)
      this.print(Node.getChild(1), depth + 1);
    return NONE;
  case K.OutlinedRetain:
    this.Printer.p("outlined retain of ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OutlinedRelease:
    this.Printer.p("outlined release of ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OutlinedInitializeWithTake:
    this.Printer.p("outlined init with take of ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OutlinedInitializeWithCopy:
  case K.OutlinedInitializeWithCopyNoValueWitness:
    this.Printer.p("outlined init with copy of ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OutlinedAssignWithTake:
  case K.OutlinedAssignWithTakeNoValueWitness:
    this.Printer.p("outlined assign with take of ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OutlinedAssignWithCopy:
  case K.OutlinedAssignWithCopyNoValueWitness:
    this.Printer.p("outlined assign with copy of ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OutlinedDestroy:
  case K.OutlinedDestroyNoValueWitness:
    this.Printer.p("outlined destroy of ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OutlinedEnumProjectDataForLoad:
    this.Printer.p("outlined enum project data for load of ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OutlinedEnumTagStore:
    this.Printer.p("outlined enum tag store of ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OutlinedEnumGetTag:
    this.Printer.p("outlined enum get tag of ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OutlinedVariable:
    this.Printer.p("outlined variable #", Node.getIndex(), " of ");
    return NONE;
  case K.OutlinedReadOnlyObject:
    this.Printer.p("outlined read-only object #", Node.getIndex(), " of ");
    return NONE;
  case K.Directness:
    this.Printer.p(toStringDirectness(Node.getIndex()), " ");
    return NONE;
  case K.AnonymousContext:
    if (this.Options.QualifyEntities && this.Options.DisplayExtensionContexts) {
      this.print(Node.getChild(1), depth + 1);
      this.Printer.p(".(unknown context at ");
      this.print(Node.getChild(0), depth + 1);
      this.Printer.p(")");
      if (Node.getNumChildren() >= 3 &&
          Node.getChild(2).getNumChildren() > 0) {
        this.Printer.p('<');
        this.print(Node.getChild(2), depth + 1);
        this.Printer.p('>');
      }
    }
    return NONE;
  case K.Extension:
    /* assert */ void 0;
    if (this.Options.QualifyEntities && this.Options.DisplayExtensionContexts) {
      this.Printer.p("(extension in ");
      // Print the module where extension is defined.
      this.print(Node.getChild(0), depth + 1, true);
      this.Printer.p("):");
    }
    this.print(Node.getChild(1), depth + 1);
    if (Node.getNumChildren() == 3) {
      // Currently the runtime does not mangle the generic signature.
      // This is an open to-do in _buildDemanglingForContext().
      if (!this.Options.PrintForTypeName)
        this.print(Node.getChild(2), depth + 1);
    }
    return NONE;
  case K.Variable:
    return this.printEntity(Node, depth, asPrefixContext, TypePrinting.WithColon,
                       /*hasName*/ true);
  case K.Function:
  case K.BoundGenericFunction:
    return this.printEntity(Node, depth, asPrefixContext,
                       TypePrinting.FunctionStyle,
                       /*hasName*/ true);
  case K.Subscript:
    return this.printEntity(
        Node, depth, asPrefixContext, TypePrinting.FunctionStyle,
        /*hasName*/ false, /*ExtraName*/ "", /*ExtraIndex*/ -1, "subscript");
  case K.Macro:
    return this.printEntity(Node, depth, asPrefixContext,
                       Node.getNumChildren() == 3? TypePrinting.WithColon
                                                  : TypePrinting.FunctionStyle,
                       /*hasName*/ true);
  case K.AccessorAttachedMacroExpansion: case K.MemberAttributeAttachedMacroExpansion: case K.MemberAttachedMacroExpansion:
  case K.PeerAttachedMacroExpansion: case K.ConformanceAttachedMacroExpansion: case K.ExtensionAttachedMacroExpansion:
  case K.PreambleAttachedMacroExpansion: case K.BodyAttachedMacroExpansion: {
    const roleNames: Record<string, string> = { Accessor: 'accessor', MemberAttribute: 'memberAttribute', Member: 'member', Peer: 'peer', Conformance: 'conformance', Extension: 'extension', Preamble: 'preamble', Body: 'body' };
    const Description = roleNames[kind.replace('AttachedMacroExpansion', '')] ?? '';
    return this.printEntity(Node, depth, asPrefixContext,
                       TypePrinting.NoType, /*hasName*/true,
                       (Description + " macro @" +
                        new NodePrinter(this.Options).printRoot(Node.getChild(2)) + " expansion #"),
                       Node.getChild(3).getIndex() + 1);
  }
  case K.FreestandingMacroExpansion:
    return this.printEntity(Node, depth, asPrefixContext, TypePrinting.NoType,
                       /*hasName*/true, "freestanding macro expansion #",
                       Node.getChild(2).getIndex() + 1);
  case K.MacroExpansionLoc:
    if (Node.getNumChildren() > 0) {
      this.Printer.p("module ");
      this.print(Node.getChild(0), depth + 1);
    }
    if (Node.getNumChildren() > 1) {
      this.Printer.p(" file ");
      this.print(Node.getChild(1), depth + 1);
    }
    if (Node.getNumChildren() > 2) {
      this.Printer.p(" line ");
      this.print(Node.getChild(2), depth + 1);
    }
    if (Node.getNumChildren() > 3) {
      this.Printer.p(" column ");
      this.print(Node.getChild(3), depth + 1);
    }
    return NONE;
  case K.MacroExpansionUniqueName:
    return this.printEntity(Node, depth, asPrefixContext, TypePrinting.NoType,
                       /*hasName*/true, "unique name #",
                       Node.getChild(2).getIndex() + 1);
  case K.GenericTypeParamDecl:
    return this.printEntity(Node, depth, asPrefixContext, TypePrinting.NoType,
                       /*hasName*/ true);
  case K.ExplicitClosure:
    return this.printEntity(
        Node, depth, asPrefixContext,
        this.Options.ShowFunctionArgumentTypes ? TypePrinting.FunctionStyle
                                          : TypePrinting.NoType,
        /*hasName*/ false, "closure #", Node.getChild(1).getIndex() + 1);
  case K.ImplicitClosure:
    return this.printEntity(Node, depth, asPrefixContext,
                       this.Options.ShowFunctionArgumentTypes
                           ? TypePrinting.FunctionStyle
                           : TypePrinting.NoType,
                       /*hasName*/ false, "implicit closure #",
                       Node.getChild(1).getIndex() + 1);
  case K.Global:
    this.printChildren(Node, depth);
    return NONE;
  case K.Suffix:
    if (this.Options.DisplayUnmangledSuffix) {
      this.Printer.p(" with unmangled suffix ", QuotedString(Node.getText()));
    }
    return NONE;
  case K.Initializer:
    return this.printEntity(Node, depth, asPrefixContext, TypePrinting.NoType,
                       /*hasName*/ false, "variable initialization expression");
  case K.PropertyWrapperBackingInitializer:
    return this.printEntity(Node, depth, asPrefixContext, TypePrinting.NoType,
                       /*hasName*/ false,
                       "property wrapper backing initializer");
  case K.PropertyWrapperInitFromProjectedValue:
    return this.printEntity(Node, depth, asPrefixContext, TypePrinting.NoType,
                       /*hasName*/ false,
                       "property wrapper init from projected value");
  case K.DefaultArgumentInitializer:
    return this.printEntity(Node, depth, asPrefixContext, TypePrinting.NoType,
                       /*hasName*/ false, "default argument ",
                       Node.getChild(1).getIndex());
  case K.DeclContext:
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.Type:
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.TypeMangling:
    if (Node.getChild(0).getKind() == K.LabelList) {
      this.printFunctionType(Node.getChild(0), Node.getChild(1).getFirstChild(),
                        depth);
    } else {
      this.print(Node.getChild(0), depth + 1);
    }
    return NONE;
  case K.Class:
  case K.Structure:
  case K.Enum:
  case K.Protocol:
  case K.TypeAlias:
  case K.OtherNominalType:
    return this.printEntity(Node, depth, asPrefixContext, TypePrinting.NoType,
                       /*hasName*/ true);
  case K.LocalDeclName:
    this.print(Node.getChild(1), depth + 1);
    if (this.Options.DisplayLocalNameContexts)
      this.Printer.p(" #", (Node.getChild(0).getIndex() + 1));
    return NONE;
  case K.PrivateDeclName:
    if (Node.getNumChildren() > 1) {
      if (this.Options.ShowPrivateDiscriminators)
        this.Printer.p('(');

      this.print(Node.getChild(1), depth + 1);

      if (this.Options.ShowPrivateDiscriminators)
        this.Printer.p(" in ", Node.getChild(0).getText(), ')');
    } else {
      if (this.Options.ShowPrivateDiscriminators) {
        this.Printer.p("(in ", Node.getChild(0).getText(), ')');
      }
    }
    return NONE;
  case K.RelatedEntityDeclName:
    this.Printer.p("related decl '", Node.getFirstChild().getText(), "' for ");
    this.print(Node.getChild(1), depth + 1);
    return NONE;
  case K.Module:
    if (this.Options.DisplayModuleNames)
      this.Printer.p(Node.getText());
    return NONE;
  case K.Identifier:
    this.Printer.p(Node.getText());
    return NONE;
  case K.Index:
    this.Printer.p(Node.getIndex());
    return NONE;
  case K.UnknownIndex:
    this.Printer.p("unknown index");
    return NONE;
  case K.FunctionType:
  case K.UncurriedFunctionType:
  case K.NoEscapeFunctionType:
  case K.AutoClosureType:
  case K.EscapingAutoClosureType:
  case K.ThinFunctionType:
  case K.CFunctionPointer:
  case K.ObjCBlock:
  case K.EscapingObjCBlock:
    this.printFunctionType(NONE, Node, depth);
    return NONE;
  case K.ClangType:
    this.Printer.p(Node.getText());
    return NONE;
  case K.ArgumentTuple:
    this.printFunctionParameters(NONE, Node, depth,
                            this.Options.ShowFunctionArgumentTypes);
    return NONE;
  case K.Tuple: {
    this.Printer.p("(");
    this.printChildren(Node, depth, ", ");
    this.Printer.p(")");
    return NONE;
  }
  case K.TupleElement: {
    const Label = this.getChildIf(Node, K.TupleElementName);
    if (Label)
      this.Printer.p(Label.getText(), ": ");

    let Type = this.getChildIf(Node, K.Type);
    /* assert */ void 0;

    this.print(Type, depth + 1);

    if (this.getChildIf(Node, K.VariadicMarker))
      this.Printer.p("...");
    return NONE;
  }
  case K.TupleElementName:
    this.Printer.p(Node.getText(), ": ");
    return NONE;
  case K.Pack: {
    this.Printer.p("Pack{");
    this.printChildren(Node, depth, ", ");
    this.Printer.p("}");
    return NONE;
  }
  case K.SILPackDirect:
  case K.SILPackIndirect: {
    this.Printer.p((kind == K.SILPackDirect ? "@direct" : "@indirect"));
    this.Printer.p(" Pack{");
    this.printChildren(Node, depth, ", ");
    this.Printer.p("}");
    return NONE;
  }
  case K.PackExpansion: {
    this.Printer.p("repeat ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  }
  case K.PackElement: {
    this.Printer.p("/* level: ", Node.getChild(1).getIndex(), " */ ");
    this.Printer.p("each ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  }
  case K.PackElementLevel:
    throw new Error("should be handled in K.PackElement");

  case K.ReturnType:
    if (Node.getNumChildren() == 0)
      this.Printer.p(Node.getText());
    else {
      this.printChildren(Node, depth);
    }
    return NONE;
  case K.RetroactiveConformance:
    if (Node.getNumChildren() != 2)
      return NONE;

    this.Printer.p("retroactive @ ");
    this.print(Node.getChild(0), depth + 1);
    this.print(Node.getChild(1), depth + 1);
    return NONE;
  case K.Weak: case K.Unowned: case K.Unmanaged:
    this.Printer.p(kind === K.Weak ? 'weak' : kind === K.Unowned ? 'unowned' : 'unowned(unsafe)', " ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.InOut:
    this.Printer.p("inout ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.Isolated:
    this.Printer.p("isolated ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.Sending:
    this.Printer.p("sending ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.CompileTimeConst:
    this.Printer.p("_const ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.Shared:
    this.Printer.p("__shared ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.Owned:
    this.Printer.p("__owned ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.NoDerivative:
    this.Printer.p("@noDerivative ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ParamLifetimeDependence: {
    this.Printer.p("lifetime dependence: ");
    const ldk = String.fromCharCode(Node.getChild(0).getIndex());
    switch (ldk) {
    case 'i':
      this.Printer.p("inherit ");
      break;
    case 's':
      this.Printer.p("scope ");
      break;
    }
    this.print(Node.getChild(1), depth + 1);
    return NONE;
  }
  case K.SelfLifetimeDependence: {
    this.Printer.p("(self lifetime dependence: ");
    const ldk = String.fromCharCode(Node.getIndex());
    switch (ldk) {
    case 'i':
      this.Printer.p("inherit) ");
      break;
    case 's':
      this.Printer.p("scope) ");
      break;
    }
    return NONE;
  }
  case K.NonObjCAttribute:
    this.Printer.p("@nonobjc ");
    return NONE;
  case K.ObjCAttribute:
    this.Printer.p("@objc ");
    return NONE;
  case K.DirectMethodReferenceAttribute:
    this.Printer.p("super ");
    return NONE;
  case K.DynamicAttribute:
    this.Printer.p("dynamic ");
    return NONE;
  case K.VTableAttribute:
    this.Printer.p("override ");
    return NONE;
  case K.FunctionSignatureSpecialization:
    this.printSpecializationPrefix(Node, "function signature specialization", depth);
    return NONE;
  case K.GenericPartialSpecialization:
    this.printSpecializationPrefix(Node, "generic partial specialization", depth,
                              "Signature = ");
    return NONE;
  case K.GenericPartialSpecializationNotReAbstracted:
    this.printSpecializationPrefix(Node,
                              "generic not-reabstracted partial specialization",
                              depth, "Signature = ");
    return NONE;
  case K.GenericSpecialization:
  case K.GenericSpecializationInResilienceDomain:
    this.printSpecializationPrefix(Node, "generic specialization", depth);
    return NONE;
  case K.GenericSpecializationPrespecialized:
    this.printSpecializationPrefix(Node, "generic pre-specialization", depth);
    return NONE;
  case K.GenericSpecializationNotReAbstracted:
    this.printSpecializationPrefix(Node, "generic not re-abstracted specialization",
                              depth);
    return NONE;
  case K.InlinedGenericFunction:
    this.printSpecializationPrefix(Node, "inlined generic function", depth);
    return NONE;
  case K.IsSerialized:
    this.Printer.p("serialized");
    return NONE;
  case K.MetatypeParamsRemoved:
    this.Printer.p("metatypes-removed");
    return NONE;
  case K.GenericSpecializationParam:
    this.print(Node.getChild(0), depth + 1);
    for (let i = 1, e = Node.getNumChildren(); i < e; ++i) {
      if (i == 1)
        this.Printer.p(" with ");
      else
        this.Printer.p(" and ");
      this.print(Node.getChild(i), depth + 1);
    }
    return NONE;
  case K.FunctionSignatureSpecializationReturn:
  case K.FunctionSignatureSpecializationParam:
    throw new Error("should be handled in printSpecializationPrefix");
  case K.FunctionSignatureSpecializationParamPayload: {
    let demangledName = NodePrinter.demangleSymbolAsString(Node.getText());
    if (demangledName.length === 0) {
      this.Printer.p(Node.getText());
    } else {
      this.Printer.p(demangledName);
    }
    return NONE;
  }
  case K.FunctionSignatureSpecializationParamKind: {
    let raw = Node.getIndex();

    let printedOptionSet = false;
    if (raw &
        FunctionSigSpecializationParamKind.ExistentialToGeneric) {
      printedOptionSet = true;
      this.Printer.p("Existential To Protocol Constrained Generic");
    }

    if (raw & FunctionSigSpecializationParamKind.Dead) {
      if (printedOptionSet)
        this.Printer.p(" and ");
      printedOptionSet = true;
      this.Printer.p("Dead");
    }
    if (raw & FunctionSigSpecializationParamKind.OwnedToGuaranteed) {
      if (printedOptionSet)
        this.Printer.p(" and ");
      printedOptionSet = true;
      this.Printer.p("Owned To Guaranteed");
    }

    if (raw & FunctionSigSpecializationParamKind.GuaranteedToOwned) {
      if (printedOptionSet)
        this.Printer.p(" and ");
      printedOptionSet = true;
      this.Printer.p("Guaranteed To Owned");
    }

    if (raw & FunctionSigSpecializationParamKind.SROA) {
      if (printedOptionSet)
        this.Printer.p(" and ");
      this.Printer.p("Exploded");
      return NONE;
    }

    if (printedOptionSet)
      return NONE;

    switch (raw as FunctionSigSpecializationParamKind) {
    case FunctionSigSpecializationParamKind.BoxToValue:
      this.Printer.p("Value Promoted from Box");
      return NONE;
    case FunctionSigSpecializationParamKind.BoxToStack:
      this.Printer.p("Stack Promoted from Box");
      return NONE;
    case FunctionSigSpecializationParamKind.InOutToOut:
      this.Printer.p("InOut Converted to Out");
      return NONE;
    case FunctionSigSpecializationParamKind.ConstantPropFunction:
      this.Printer.p("Constant Propagated Function");
      return NONE;
    case FunctionSigSpecializationParamKind.ConstantPropGlobal:
      this.Printer.p("Constant Propagated Global");
      return NONE;
    case FunctionSigSpecializationParamKind.ConstantPropInteger:
      this.Printer.p("Constant Propagated Integer");
      return NONE;
    case FunctionSigSpecializationParamKind.ConstantPropFloat:
      this.Printer.p("Constant Propagated Float");
      return NONE;
    case FunctionSigSpecializationParamKind.ConstantPropString:
      this.Printer.p("Constant Propagated String");
      return NONE;
    case FunctionSigSpecializationParamKind.ConstantPropKeyPath:
      this.Printer.p("Constant Propagated KeyPath");
      return NONE;
    case FunctionSigSpecializationParamKind.ClosureProp:
      this.Printer.p("Closure Propagated");
      return NONE;
    case FunctionSigSpecializationParamKind.ExistentialToGeneric:
    case FunctionSigSpecializationParamKind.Dead:
    case FunctionSigSpecializationParamKind.OwnedToGuaranteed:
    case FunctionSigSpecializationParamKind.GuaranteedToOwned:
    case FunctionSigSpecializationParamKind.SROA:
      throw new Error("option sets should have been handled earlier");
    }
    return NONE;
  }
  case K.SpecializationPassID:
    this.Printer.p(Node.getIndex());
    return NONE;
  case K.BuiltinTypeName:
    this.Printer.p(Node.getText());
    return NONE;
  case K.BuiltinTupleType:
    this.Printer.p("Builtin.TheTupleType");
    return NONE;
  case K.Number:
    this.Printer.p(Node.getIndex());
    return NONE;
  case K.InfixOperator:
    this.Printer.p(Node.getText(), " infix");
    return NONE;
  case K.PrefixOperator:
    this.Printer.p(Node.getText(), " prefix");
    return NONE;
  case K.PostfixOperator:
    this.Printer.p(Node.getText(), " postfix");
    return NONE;
  case K.LazyProtocolWitnessTableAccessor:
    this.Printer.p("lazy protocol witness table accessor for type ");
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(" and conformance ");
    this.print(Node.getChild(1), depth + 1);
    return NONE;
  case K.LazyProtocolWitnessTableCacheVariable:
    this.Printer.p("lazy protocol witness table cache variable for type ");
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(" and conformance ");
    this.print(Node.getChild(1), depth + 1);
    return NONE;
  case K.ProtocolSelfConformanceWitnessTable:
    this.Printer.p("protocol self-conformance witness table for ");
    this.print(Node.getFirstChild(), depth + 1);
    return NONE;
  case K.ProtocolWitnessTableAccessor:
    this.Printer.p("protocol witness table accessor for ");
    this.print(Node.getFirstChild(), depth + 1);
    return NONE;
  case K.ProtocolWitnessTable:
    this.Printer.p("protocol witness table for ");
    this.print(Node.getFirstChild(), depth + 1);
    return NONE;
  case K.ProtocolWitnessTablePattern:
    this.Printer.p("protocol witness table pattern for ");
    this.print(Node.getFirstChild(), depth + 1);
    return NONE;
  case K.GenericProtocolWitnessTable:
    this.Printer.p("generic protocol witness table for ");
    this.print(Node.getFirstChild(), depth + 1);
    return NONE;
  case K.GenericProtocolWitnessTableInstantiationFunction:
    this.Printer.p("instantiation function for generic protocol witness table for ");
    this.print(Node.getFirstChild(), depth + 1);
    return NONE;
  case K.ResilientProtocolWitnessTable:
    this.Printer.p("resilient protocol witness table for ");
    this.print(Node.getFirstChild(), depth + 1);
    return NONE;
  case K.VTableThunk: {
    this.Printer.p("vtable thunk for ");
    this.print(Node.getChild(1), depth + 1);
    this.Printer.p(" dispatching to ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  }
  case K.ProtocolSelfConformanceWitness: {
    this.Printer.p("protocol self-conformance witness for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  }
  case K.ProtocolWitness: {
    this.Printer.p("protocol witness for ");
    this.print(Node.getChild(1), depth + 1);
    this.Printer.p(" in conformance ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  }
  case K.PartialApplyForwarder:
    if (this.Options.ShortenPartialApply)
      this.Printer.p("partial apply");
    else
      this.Printer.p("partial apply forwarder");

    if (Node.hasChildren()) {
      this.Printer.p(" for ");
      this.printChildren(Node, depth);
    }
    return NONE;
  case K.PartialApplyObjCForwarder:
    if (this.Options.ShortenPartialApply)
      this.Printer.p("partial apply");
    else
      this.Printer.p("partial apply ObjC forwarder");

    if (Node.hasChildren()) {
      this.Printer.p(" for ");
      this.printChildren(Node, depth);
    }
    return NONE;
  case K.KeyPathGetterThunkHelper:
  case K.KeyPathSetterThunkHelper:
    if (Node.getKind() == K.KeyPathGetterThunkHelper)
      this.Printer.p("key path getter for ");
    else
      this.Printer.p("key path setter for ");

    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(" : ");
    for (let index = 1; index < Node.getNumChildren(); ++index) {
      let Child = Node.getChild(index);
      if (Child.getKind() == K.IsSerialized)
        this.Printer.p(", ");
      this.print(Child, depth + 1);
    }
    return NONE;
  case K.KeyPathEqualsThunkHelper:
  case K.KeyPathHashThunkHelper: {
    this.Printer.p("key path index ", (Node.getKind() == K.KeyPathEqualsThunkHelper
               ? "equality" : "hash"), " operator for ");

    let lastChildIndex = Node.getNumChildren();
    let lastChild = Node.getChild(lastChildIndex - 1);
    if (lastChild.getKind() == K.IsSerialized) {
      --lastChildIndex;
      lastChild = Node.getChild(lastChildIndex - 1);
    }

    if (lastChild.getKind() == K.DependentGenericSignature) {
      this.print(lastChild, depth + 1);
      --lastChildIndex;
    }

    this.Printer.p("(");
    for (let i = 0; i < lastChildIndex; ++i) {
      if (i != 0)
        this.Printer.p(", ");
      this.print(Node.getChild(i), depth + 1);
    }
    this.Printer.p(")");
    return NONE;
  }
  case K.FieldOffset: {
    this.print(Node.getChild(0), depth + 1); // directness
    this.Printer.p("field offset for ");
    let entity = Node.getChild(1);
    this.print(entity, depth + 1, /*asContext*/ false);
    return NONE;
  }
  case K.EnumCase: {
    this.Printer.p("enum case for ");
    let entity = Node.getChild(0);
    this.print(entity, depth + 1, /*asContext*/ false);
    return NONE;
  }
  case K.ReabstractionThunk:
  case K.ReabstractionThunkHelper: {
    if (this.Options.ShortenThunk) {
      this.Printer.p("thunk for ");
      this.print(Node.getChild(Node.getNumChildren() - 1), depth + 1);
      return NONE;
    }
    this.Printer.p("reabstraction thunk ");
    if (Node.getKind() == K.ReabstractionThunkHelper)
      this.Printer.p("helper ");
    let idx = 0;
    if (Node.getNumChildren() == 3) {
      let generics = Node.getChild(0);
      idx = 1;
      this.print(generics, depth + 1);
      this.Printer.p(" ");
    }
    this.Printer.p("from ");
    this.print(Node.getChild(idx + 1), depth + 1);
    this.Printer.p(" to ");
    this.print(Node.getChild(idx), depth + 1);
    return NONE;
  }
  case K.ReabstractionThunkHelperWithGlobalActor: {
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(" with global actor constraint ");
    this.print(Node.getChild(1), depth + 1);
    return NONE;
  }
  case K.ReabstractionThunkHelperWithSelf: {
    this.Printer.p("reabstraction thunk ");
    let idx = 0;
    if (Node.getNumChildren() == 4) {
      let generics = Node.getChild(0);
      idx = 1;
      this.print(generics, depth + 1);
      this.Printer.p(" ");
    }
    this.Printer.p("from ");
    this.print(Node.getChild(idx + 2), depth + 1);
    this.Printer.p(" to ");
    this.print(Node.getChild(idx + 1), depth + 1);
    this.Printer.p(" self ");
    this.print(Node.getChild(idx), depth + 1);
    return NONE;
  }
  case K.AutoDiffFunction:
  case K.AutoDiffDerivativeVTableThunk: {
    let prefixEndIndex = 0;
    while (prefixEndIndex != Node.getNumChildren() &&
           Node.getChild(prefixEndIndex).getKind()
              != K.AutoDiffFunctionKind)
      ++prefixEndIndex;
    let funcKind = Node.getChild(prefixEndIndex);
    let paramIndices = Node.getChild(prefixEndIndex + 1);
    let resultIndices = Node.getChild(prefixEndIndex + 2);
    if (kind == K.AutoDiffDerivativeVTableThunk)
      this.Printer.p("vtable thunk for ");
    this.print(funcKind, depth + 1);
    this.Printer.p(" of ");
    let optionalGenSig = NONE;
    for (let i = 0; i < prefixEndIndex; ++i) {
      // The last node may be a generic signature. If so, this.print it later.
      if (i == prefixEndIndex - 1 &&
          Node.getChild(i).getKind()
              == K.DependentGenericSignature) {
        optionalGenSig = Node.getChild(i);
        break;
      }
      this.print(Node.getChild(i), depth + 1);
    }
    if (this.Options.ShortenThunk)
      return NONE;
    this.Printer.p(" with respect to parameters ");
    this.print(paramIndices, depth + 1);
    this.Printer.p(" and results ");
    this.print(resultIndices, depth + 1);
    if (optionalGenSig && this.Options.DisplayWhereClauses) {
      this.Printer.p(" with ");
      this.print(optionalGenSig, depth + 1);
    }
    return NONE;
  }
  case K.AutoDiffSelfReorderingReabstractionThunk: {
    this.Printer.p("autodiff self-reordering reabstraction thunk ");
    let childIt = 0;
    let fromType = Node.getChild(childIt++);
    let toType = Node.getChild(childIt++);
    if (this.Options.ShortenThunk) {
      this.Printer.p("for ");
      this.print(fromType, depth + 1);
      return NONE;
    }
    let optionalGenSig =
        Node.getChild(childIt).getKind() == K.DependentGenericSignature
            ? Node.getChild(childIt++) : NONE;
    this.Printer.p("for ");
    this.print(Node.getChild(childIt++), depth + 1); // kind
    if (optionalGenSig) {
      this.print(optionalGenSig, depth + 1);
      this.Printer.p(' ');
    }
    this.Printer.p(" from ");
    this.print(fromType, depth + 1);
    this.Printer.p(" to ");
    this.print(toType, depth + 1);
    return NONE;
  }
  case K.AutoDiffSubsetParametersThunk: {
    this.Printer.p("autodiff subset parameters thunk for ");
    let currentIndex = Node.getNumChildren() - 1;
    let toParamIndices = Node.getChild(currentIndex--);
    let resultIndices = Node.getChild(currentIndex--);
    let paramIndices = Node.getChild(currentIndex--);
    let kind = Node.getChild(currentIndex--);
    this.print(kind, depth + 1);
    this.Printer.p(" from ");
    // Print the "from" thing.
    if (currentIndex == 0) {
      this.print(Node.getFirstChild(), depth + 1); // the "from" type
    } else {
      for (let i = 0; i < currentIndex; ++i) // the "from" global
        this.print(Node.getChild(i), depth + 1);
    }
    if (this.Options.ShortenThunk)
      return NONE;
    this.Printer.p(" with respect to parameters ");
    this.print(paramIndices, depth + 1);
    this.Printer.p(" and results ");
    this.print(resultIndices, depth + 1);
    this.Printer.p(" to parameters ");
    this.print(toParamIndices, depth + 1);
    if (currentIndex > 0) {
      this.Printer.p(" of type ");
      this.print(Node.getChild(currentIndex), depth + 1); // "to" type
    }
    return NONE;
  }
  case K.AutoDiffFunctionKind: {
    let kind = String.fromCharCode(Node.getIndex());
    switch (kind) {
    case 'f':
      this.Printer.p("forward-mode derivative");
      break;
    case 'r':
      this.Printer.p("reverse-mode derivative");
      break;
    case 'd':
      this.Printer.p("differential");
      break;
    case 'p':
      this.Printer.p("pullback");
      break;
    }
    return NONE;
  }
  case K.DifferentiabilityWitness: {
    let kindNodeIndex = Node.getNumChildren() - (
        Node.getLastChild().getKind() == K.DependentGenericSignature
            ? 4 : 3);
    let kind =
        String.fromCharCode(Node.getChild(kindNodeIndex).getIndex());
    switch (kind) {
    case 'f':
      this.Printer.p("forward-mode");
      break;
    case 'r':
      this.Printer.p("reverse-mode");
      break;
    case 'd':
      this.Printer.p("normal");
      break;
    case 'l':
      this.Printer.p("linear");
      break;
    case '\0':
      /* assert */ void 0;
    }
    this.Printer.p(" differentiability witness for ");
    let idx = 0;
    for (let numChildren = Node.getNumChildren();
         idx < numChildren &&
             Node.getChild(idx).getKind() != K.Index; ++idx)
      this.print(Node.getChild(idx), depth + 1);
    ++idx; // kind (handled earlier)
    this.Printer.p(" with respect to parameters ");
    this.print(Node.getChild(idx++), depth + 1); // parameter indices
    this.Printer.p(" and results ");
    this.print(Node.getChild(idx++), depth + 1);
    if (idx < Node.getNumChildren()) {
      let genSig = Node.getChild(idx);
      /* assert */ void 0;
      this.Printer.p(" with ");
      this.print(genSig, depth + 1);
    }
    return NONE;
  }
  case K.IndexSubset: {
    this.Printer.p('{');
        let text = Node.getText();
    let printedAnyIndex = false;
    for (let i = 0, n = text.length; i < n; ++i) {
      if (text[i] != 'S') {
        /* assert */ void 0;
        continue;
      }
      if (printedAnyIndex)
        this.Printer.p(", ");
      this.Printer.p(i);
      printedAnyIndex = true;
    }
    this.Printer.p('}');
    return NONE;
  }
  case K.MergedFunction:
    if (!this.Options.ShortenThunk) {
      this.Printer.p("merged ");
    }
    return NONE;
  case K.TypeSymbolicReference:
    this.Printer.p("type symbolic reference 0x");
    this.Printer.writeHex(Node.getIndex());
    return NONE;
  case K.OpaqueTypeDescriptorSymbolicReference:
    this.Printer.p("opaque type symbolic reference 0x");
    this.Printer.writeHex(Node.getIndex());
    return NONE;
  case K.DistributedThunk:
    if (!this.Options.ShortenThunk) {
      this.Printer.p("distributed thunk ");
    }
    return NONE;
  case K.DistributedAccessor:
    if (!this.Options.ShortenThunk) {
      this.Printer.p("distributed accessor for ");
    }
    return NONE;
  case K.AccessibleFunctionRecord:
    if (!this.Options.ShortenThunk) {
      this.Printer.p("accessible function runtime record for ");
    }
    return NONE;
  case K.DynamicallyReplaceableFunctionKey:
    if (!this.Options.ShortenThunk) {
      this.Printer.p("dynamically replaceable key for ");
    }
    return NONE;
  case K.DynamicallyReplaceableFunctionImpl:
    if (!this.Options.ShortenThunk) {
      this.Printer.p("dynamically replaceable thunk for ");
    }
    return NONE;
  case K.DynamicallyReplaceableFunctionVar:
    if (!this.Options.ShortenThunk) {
      this.Printer.p("dynamically replaceable variable for ");
    }
    return NONE;
  case K.BackDeploymentThunk:
    if (!this.Options.ShortenThunk) {
      this.Printer.p("back deployment thunk for ");
    }
    return NONE;
  case K.BackDeploymentFallback:
    this.Printer.p("back deployment fallback for ");
    return NONE;
  case K.ProtocolSymbolicReference:
    this.Printer.p("protocol symbolic reference 0x");
    this.Printer.writeHex(Node.getIndex());
    return NONE;
  case K.GenericTypeMetadataPattern:
    this.Printer.p("generic type metadata pattern for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.Metaclass:
    this.Printer.p("metaclass for ");
    this.print(Node.getFirstChild(), depth + 1);
    return NONE;
  case K.ProtocolSelfConformanceDescriptor:
    this.Printer.p("protocol self-conformance descriptor for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ProtocolConformanceDescriptor:
    this.Printer.p("protocol conformance descriptor for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ProtocolConformanceDescriptorRecord:
    this.Printer.p("protocol conformance descriptor runtime record for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ProtocolDescriptor:
    this.Printer.p("protocol descriptor for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ProtocolDescriptorRecord:
    this.Printer.p("protocol descriptor runtime record for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ProtocolRequirementsBaseDescriptor:
    this.Printer.p("protocol requirements base descriptor for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.FullTypeMetadata:
    this.Printer.p("full type metadata for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.TypeMetadata:
    this.Printer.p("type metadata for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.TypeMetadataAccessFunction:
    this.Printer.p("type metadata accessor for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.TypeMetadataInstantiationCache:
    this.Printer.p("type metadata instantiation cache for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.TypeMetadataInstantiationFunction:
    this.Printer.p("type metadata instantiation function for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.TypeMetadataSingletonInitializationCache:
    this.Printer.p("type metadata singleton initialization cache for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.TypeMetadataCompletionFunction:
    this.Printer.p("type metadata completion function for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.TypeMetadataDemanglingCache:
    this.Printer.p("demangling cache variable for type metadata for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.TypeMetadataLazyCache:
    this.Printer.p("lazy cache variable for type metadata for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.AssociatedConformanceDescriptor:
    this.Printer.p("associated conformance descriptor for ");
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(".");
    this.print(Node.getChild(1), depth + 1);
    this.Printer.p(": ");
    this.print(Node.getChild(2), depth + 1);
    return NONE;
  case K.DefaultAssociatedConformanceAccessor:
    this.Printer.p("default associated conformance accessor for ");
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(".");
    this.print(Node.getChild(1), depth + 1);
    this.Printer.p(": ");
    this.print(Node.getChild(2), depth + 1);
    return NONE;
  case K.AssociatedTypeDescriptor:
    this.Printer.p("associated type descriptor for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.AssociatedTypeMetadataAccessor:
    this.Printer.p("associated type metadata accessor for ");
    this.print(Node.getChild(1), depth + 1);
    this.Printer.p(" in ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.BaseConformanceDescriptor:
    this.Printer.p("base conformance descriptor for ");
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(": ");
    this.print(Node.getChild(1), depth + 1);
    return NONE;
  case K.DefaultAssociatedTypeMetadataAccessor:
    this.Printer.p("default associated type metadata accessor for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.AssociatedTypeWitnessTableAccessor:
    this.Printer.p("associated type witness table accessor for ");
    this.print(Node.getChild(1), depth + 1);
    this.Printer.p(" : ");
    this.print(Node.getChild(2), depth + 1);
    this.Printer.p(" in ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.BaseWitnessTableAccessor:
    this.Printer.p("base witness table accessor for ");
    this.print(Node.getChild(1), depth + 1);
    this.Printer.p(" in ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ClassMetadataBaseOffset:
    this.Printer.p("class metadata base offset for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.PropertyDescriptor:
    this.Printer.p("property descriptor for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.NominalTypeDescriptor:
    this.Printer.p("nominal type descriptor for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.NominalTypeDescriptorRecord:
    this.Printer.p("nominal type descriptor runtime record for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OpaqueTypeDescriptor:
    this.Printer.p("opaque type descriptor for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OpaqueTypeDescriptorRecord:
    this.Printer.p("opaque type descriptor runtime record for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OpaqueTypeDescriptorAccessor:
    this.Printer.p("opaque type descriptor accessor for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OpaqueTypeDescriptorAccessorImpl:
    this.Printer.p("opaque type descriptor accessor impl for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OpaqueTypeDescriptorAccessorKey:
    this.Printer.p("opaque type descriptor accessor key for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.OpaqueTypeDescriptorAccessorVar:
    this.Printer.p("opaque type descriptor accessor var for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.CoroutineContinuationPrototype:
    this.Printer.p("coroutine continuation prototype for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ValueWitness:
    this.Printer.p(toStringValueWitness(Node.getFirstChild().getIndex()));
    if (this.Options.ShortenValueWitness) this.Printer.p(" for ");
    else this.Printer.p(" value witness for ");
    this.print(Node.getChild(1), depth + 1);
    return NONE;
  case K.ValueWitnessTable:
    this.Printer.p("value witness table for ");
    this.print(Node.getFirstChild(), depth + 1);
    return NONE;
  case K.BoundGenericClass:
  case K.BoundGenericStructure:
  case K.BoundGenericEnum:
  case K.BoundGenericProtocol:
  case K.BoundGenericOtherNominalType:
  case K.BoundGenericTypeAlias:
    this.printBoundGeneric(Node, depth);
    return NONE;
  case K.DynamicSelf:
    this.Printer.p("Self");
    return NONE;
  case K.SILBoxType: {
    this.Printer.p("@box ");
    let type = Node.getChild(0);
    this.print(type, depth + 1);
    return NONE;
  }
  case K.Metatype: {
    let Idx = 0;
    if (Node.getNumChildren() == 2) {
      let repr = Node.getChild(Idx);
      this.print(repr, depth + 1);
      this.Printer.p(" ");
      ++Idx;
    }
    let type = Node.getChild(Idx).getChild(0);
    this.printWithParens(type, depth);
    if (this.isExistentialType(type)) {
      this.Printer.p(".Protocol");
    } else {
      this.Printer.p(".Type");
    }
    return NONE;
  }
  case K.ConstrainedExistential: {
    this.Printer.p("any ");
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p("<");
    this.print(Node.getChild(1), depth + 1);
    this.Printer.p(">");
    return NONE;
  }
  case K.ConstrainedExistentialRequirementList: {
    this.printChildren(Node, depth, ", ");
    return NONE;
  }
  case K.ExistentialMetatype: {
    let Idx = 0;
    if (Node.getNumChildren() == 2) {
      let repr = Node.getChild(Idx);
      this.print(repr, depth + 1);
      this.Printer.p(" ");
      ++Idx;
    }

    let type = Node.getChild(Idx);
    this.print(type, depth + 1);
    this.Printer.p(".Type");
    return NONE;
  }
  case K.ConstrainedExistentialSelf:
    this.Printer.p("Self");
    return NONE;
  case K.MetatypeRepresentation: {
    this.Printer.p(Node.getText());
    return NONE;
  }
  case K.AssociatedTypeRef:
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p('.', Node.getChild(1).getText());
    return NONE;
  case K.ProtocolList: {
    let type_list = Node.getChild(0);
    if (!type_list)
      return NONE;
    if (type_list.getNumChildren() == 0)
      this.Printer.p("Any");
    else
      this.printChildren(type_list, depth, " & ");
    return NONE;
  }
  case K.ProtocolListWithClass: {
    if (Node.getNumChildren() < 2)
      return NONE;
    let protocols = Node.getChild(0);
    let superclass = Node.getChild(1);
    this.print(superclass, depth + 1);
    this.Printer.p(" & ");
    if (protocols.getNumChildren() < 1)
      return NONE;
    let type_list = protocols.getChild(0);
    this.printChildren(type_list, depth, " & ");
    return NONE;
  }
  case K.ProtocolListWithAnyObject: {
    if (Node.getNumChildren() < 1)
      return NONE;
    let protocols = Node.getChild(0);
    if (protocols.getNumChildren() < 1)
      return NONE;
    let type_list = protocols.getChild(0);
    if (type_list.getNumChildren() > 0) {
      this.printChildren(type_list, depth, " & ");
      this.Printer.p(" & ");
    }
    if (this.Options.QualifyEntities && this.Options.DisplayStdlibModule)
      this.Printer.p(STDLIB_NAME, ".");
    this.Printer.p("AnyObject");
    return NONE;
  }
  case K.AssociatedType:
    // Don't this.print for now.
    return NONE;
  case K.OwningAddressor:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "owningAddressor");
  case K.OwningMutableAddressor:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "owningMutableAddressor");
  case K.NativeOwningAddressor:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "nativeOwningAddressor");
  case K.NativeOwningMutableAddressor:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "nativeOwningMutableAddressor");
  case K.NativePinningAddressor:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "nativePinningAddressor");
  case K.NativePinningMutableAddressor:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "nativePinningMutableAddressor");
  case K.UnsafeAddressor:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "unsafeAddressor");
  case K.UnsafeMutableAddressor:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "unsafeMutableAddressor");
  case K.GlobalGetter:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "getter");
  case K.Getter:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "getter");
  case K.Setter:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "setter");
  case K.MaterializeForSet:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "materializeForSet");
  case K.WillSet:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "willset");
  case K.DidSet:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "didset");
  case K.ReadAccessor:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "read");
  case K.ModifyAccessor:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "modify");
  case K.InitAccessor:
    return this.printAbstractStorage(Node.getFirstChild(), depth, asPrefixContext,
                                "init");
  case K.Allocator:
    return this.printEntity(
        Node, depth, asPrefixContext, TypePrinting.FunctionStyle,
        /*hasName*/ false,
        this.isClassType(Node.getChild(0)) ? "__allocating_init" : "init");
  case K.Constructor:
    return this.printEntity(Node, depth, asPrefixContext,
                       TypePrinting.FunctionStyle,
                       /*hasName*/ Node.getNumChildren() > 2, "init");
  case K.Destructor:
    return this.printEntity(Node, depth, asPrefixContext, TypePrinting.NoType,
                       /*hasName*/ false, "deinit");
  case K.Deallocator:
    return this.printEntity(Node, depth, asPrefixContext, TypePrinting.NoType,
                       /*hasName*/ false,
                       this.isClassType(Node.getChild(0)) ? "__deallocating_deinit"
                                                      : "deinit");
  case K.IVarInitializer:
    return this.printEntity(Node, depth, asPrefixContext, TypePrinting.NoType,
                       /*hasName*/ false, "__ivar_initializer");
  case K.IVarDestroyer:
    return this.printEntity(Node, depth, asPrefixContext, TypePrinting.NoType,
                       /*hasName*/ false, "__ivar_destroyer");
  case K.ProtocolConformance: {
    let child0 = Node.getChild(0);
    let child1 = Node.getChild(1);
    let child2 = Node.getChild(2);
    if (Node.getNumChildren() == 4) {
      // TODO: check if this is correct
      this.Printer.p("property behavior storage of ");
      this.print(child2, depth + 1);
      this.Printer.p(" in ");
      this.print(child0, depth + 1);
      this.Printer.p(" : ");
      this.print(child1, depth + 1);
    } else {
      this.print(child0, depth + 1);
      if (this.Options.DisplayProtocolConformances) {
        this.Printer.p(" : ");
        this.print(child1, depth + 1);
        this.Printer.p(" in ");
        this.print(child2, depth + 1);
      }
    }
    return NONE;
  }
  case K.TypeList:
    this.printChildren(Node, depth);
    return NONE;
  case K.LabelList:
    return NONE;
  case K.ImplDifferentiabilityKind:
    this.Printer.p("@differentiable");
    switch (String.fromCharCode(Node.getIndex())) {
    case 'd':
      break;
    case 'l':
      this.Printer.p("(_linear)");
      break;
    case 'f':
      this.Printer.p("(_forward)");
      break;
    case 'r':
      this.Printer.p("(reverse)");
      break;
    case '\0':
      /* assert */ void 0;
    }
    return NONE;
  case K.ImplEscaping:
    this.Printer.p("@escaping");
    return NONE;
  case K.ImplErasedIsolation:
    this.Printer.p("@isolated(any)");
    return NONE;
  case K.ImplSendingResult:
    this.Printer.p("sending");
    return NONE;
  case K.ImplConvention:
    this.Printer.p(Node.getText());
    return NONE;
  case K.ImplParameterResultDifferentiability:
    // Skip if text is empty.
    if (Node.getText().length === 0)
      return NONE;
    // Otherwise, this.print with trailing space.
    this.Printer.p(Node.getText(), ' ');
    return NONE;
  case K.ImplParameterSending:
    // Skip if text is empty.
    if (Node.getText().length === 0)
      return NONE;
    // Otherwise, this.print with trailing space.
    this.Printer.p(Node.getText(), ' ');
    return NONE;
  case K.ImplFunctionAttribute:
    this.Printer.p(Node.getText());
    return NONE;
  case K.ImplFunctionConvention:
    this.Printer.p("@convention(");
    switch (Node.getNumChildren()) {
    case 1:
      this.Printer.p(Node.getChild(0).getText());
      break;
    case 2:
      this.Printer.p(Node.getChild(0).getText(), ", mangledCType: \"");
      this.print(Node.getChild(1), depth + 1);
      this.Printer.p('"');
      break;
    default:
      /* assert */ void 0;
    }
    this.Printer.p(')');
    return NONE;
  case K.ImplFunctionConventionName:
    /* assert */ void 0;
    return NONE;
  case K.ImplErrorResult:
    this.Printer.p("@error ");
    this.printChildren(Node, depth, " ");
    return NONE;
  case K.ImplYield:
    this.Printer.p("@yields ");
    this.printChildren(Node, depth, " ");
    return NONE;
  case K.ImplParameter:
  case K.ImplResult:
    // Children: `convention, differentiability?, type`
    // Print convention.
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(" ");
    // Print differentiability, if it exists.
    if (Node.getNumChildren() == 3)
      this.print(Node.getChild(1), depth + 1);
    // Print differentiability and sending if it exists.
    if (Node.getNumChildren() == 4) {
      this.print(Node.getChild(1), depth + 1);
      this.print(Node.getChild(2), depth + 1);
    }
    // Print type.
    this.print(Node.getLastChild(), depth + 1);
    return NONE;
  case K.ImplFunctionType:
    this.printImplFunctionType(Node, depth);
    return NONE;
  case K.ImplInvocationSubstitutions:
    this.Printer.p("for <");
    this.printChildren(Node.getChild(0), depth, ", ");
    this.Printer.p('>');
    return NONE;
  case K.ImplPatternSubstitutions:
    this.Printer.p("@substituted ");
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(" for <");
    this.printChildren(Node.getChild(1), depth, ", ");
    this.Printer.p('>');
    return NONE;
  case K.ErrorType:
    this.Printer.p("<ERROR TYPE>");
    return NONE;
      
  case K.DependentPseudogenericSignature:
  case K.DependentGenericSignature: {
    this.printGenericSignature(Node, depth);
    return NONE;
  }
  case K.DependentGenericParamCount:
  case K.DependentGenericParamPackMarker:
    throw new Error("should be printed as a child of a " +
                        "DependentGenericSignature");
  case K.DependentGenericConformanceRequirement: {
    let type = Node.getChild(0);
    let reqt = Node.getChild(1);
    this.print(type, depth + 1);
    this.Printer.p(": ");
    this.print(reqt, depth + 1);
    return NONE;
  }
  case K.DependentGenericInverseConformanceRequirement: {
    let type = Node.getChild(0);
    this.print(type, depth + 1);
    this.Printer.p(": ~");
    switch (Node.getChild(1).getIndex()) {
    case 0: this.Printer.p("Swift.", "Copyable"); break;
    case 1: this.Printer.p("Swift.", "Escapable"); break;

    default:
      this.Printer.p("Swift.<bit ", Node.getChild(1).getIndex(), ">");
      break;
    }
    return NONE;
  }
  case K.DependentGenericLayoutRequirement: {
    let type = Node.getChild(0);
    let layout = Node.getChild(1);
    this.print(type, depth + 1);
    this.Printer.p(": ");
    /* assert */ void 0;
    /* assert */ void 0;
    let c = layout.getText()[0];
    let name = '';
    if (c == 'U') {
      name = "_UnknownLayout";
    } else if (c == 'R') {
      name = "_RefCountedObject";
    } else if (c == 'N') {
      name = "_NativeRefCountedObject";
    } else if (c == 'C') {
      name = "AnyObject";
    } else if (c == 'D') {
      name = "_NativeClass";
    } else if (c == 'T') {
      name = "_Trivial";
    } else if (c == 'E' || c == 'e') {
      name = "_Trivial";
    } else if (c == 'M' || c == 'm') {
      name = "_TrivialAtMost";
    }
    this.Printer.p(name);
    if (Node.getNumChildren() > 2) {
      this.Printer.p("(");
      this.print(Node.getChild(2), depth + 1);
      if (Node.getNumChildren() > 3) {
        this.Printer.p(", ");
        this.print(Node.getChild(3), depth + 1);
      }
      this.Printer.p(")");
    }
    return NONE;
  }
  case K.DependentGenericSameTypeRequirement: {
    let fst = Node.getChild(0);
    let snd = Node.getChild(1);

    this.print(fst, depth + 1);
    this.Printer.p(" == ");
    this.print(snd, depth + 1);
    return NONE;
  }
  case K.DependentGenericSameShapeRequirement: {
    let fst = Node.getChild(0);
    let snd = Node.getChild(1);

    this.print(fst, depth + 1);
    this.Printer.p(".shape == ");
    this.print(snd, depth + 1);
    this.Printer.p(".shape");
    return NONE;
  }
  case K.DependentGenericParamType: {
    let index = Node.getChild(1).getIndex();
    let depth = Node.getChild(0).getIndex();
    this.Printer.p(this.Options.GenericParameterName(depth, index));
    return NONE;
  }
  case K.DependentGenericType: {
    let sig = Node.getChild(0);
    let depTy = Node.getChild(1);
    this.print(sig, depth + 1);
    if (this.needSpaceBeforeType(depTy))
      this.Printer.p(' ');
    this.print(depTy, depth + 1);
    return NONE;
  }
  case K.DependentMemberType: {
    let base = Node.getChild(0);
    this.print(base, depth + 1);
    this.Printer.p('.');
    let assocTy = Node.getChild(1);
    this.print(assocTy, depth + 1);
    return NONE;
  }
  case K.DependentAssociatedTypeRef: {
    if (Node.getNumChildren() > 1) {
      this.print(Node.getChild(1), depth + 1);
      this.Printer.p('.');
    }
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  }
  case K.ReflectionMetadataBuiltinDescriptor:
    this.Printer.p("reflection metadata builtin descriptor ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ReflectionMetadataFieldDescriptor:
    this.Printer.p("reflection metadata field descriptor ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ReflectionMetadataAssocTypeDescriptor:
    this.Printer.p("reflection metadata associated type descriptor ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ReflectionMetadataSuperclassDescriptor:
    this.Printer.p("reflection metadata superclass descriptor ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;

  case K.ConcurrentFunctionType:
    this.Printer.p("@Sendable ");
    return NONE;
  case K.DifferentiableFunctionType: {
    this.Printer.p("@differentiable");
    let kind = String.fromCharCode(Node.getIndex());
    switch (kind) {
    case 'f':
      this.Printer.p("(_forward)");
      break;
    case 'r':
      this.Printer.p("(reverse)");
      break;
    case 'l':
      this.Printer.p("(_linear)");
      break;
    case 'd':
      break;
    case '\0':
      /* assert */ void 0;
    }
    this.Printer.p(' ');
    return NONE;
  }
  case K.GlobalActorFunctionType: {
    if (Node.getNumChildren() > 0) {
      this.Printer.p('@');
      this.print(Node.getChild(0), depth + 1);
      this.Printer.p(' ');
    }
    return NONE;
  }
  case K.IsolatedAnyFunctionType:
    this.Printer.p("@isolated(any) ");
    return NONE;
  case K.SendingResultFunctionType:
    this.Printer.p("sending ");
    return NONE;
  case K.AsyncAnnotation:
    this.Printer.p(" async");
    return NONE;
  case K.ThrowsAnnotation:
    this.Printer.p(" throws");
    return NONE;
  case K.TypedThrowsAnnotation:
    this.Printer.p(" throws(");
    if (Node.getNumChildren() == 1)
      this.print(Node.getChild(0), depth + 1);
    this.Printer.p(")");
    return NONE;
  case K.EmptyList:
    this.Printer.p(" empty-list ");
    return NONE;
  case K.FirstElementMarker:
    this.Printer.p(" first-element-marker ");
    return NONE;
  case K.VariadicMarker:
    this.Printer.p(" variadic-marker ");
    return NONE;
  case K.SILBoxTypeWithLayout: {
    /* assert */ void 0;
    let layout = Node.getChild(0);
    /* assert */ void 0;
    let signature = NONE, genericArgs = NONE;
    if (Node.getNumChildren() == 3) {
      signature = Node.getChild(1);
      /* assert */ void 0;
      genericArgs = Node.getChild(2);
      /* assert */ void 0;

      this.print(signature, depth + 1);
      this.Printer.p(' ');
    }
    this.print(layout, depth + 1);
    if (genericArgs) {
      this.Printer.p(" <");
      for (let i = 0, e = genericArgs.getNumChildren(); i < e; ++i) {
        if (i > 0)
          this.Printer.p(", ");
        this.print(genericArgs.getChild(i), depth + 1);
      }
      this.Printer.p('>');
    }
    return NONE;
  }
  case K.SILBoxLayout:
    this.Printer.p('{');
    for (let i = 0; i < Node.getNumChildren(); ++i) {
      if (i > 0)
        this.Printer.p(',');
      this.Printer.p(' ');
      this.print(Node.getChild(i), depth + 1);
    }
    this.Printer.p(" }");
    return NONE;
  case K.SILBoxImmutableField:
  case K.SILBoxMutableField:
    this.Printer.p((Node.getKind() == K.SILBoxImmutableField
      ? "let "
      : "var "));
    /* assert */ void 0;
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.AssocTypePath:
    this.printChildren(Node, depth, ".");
    return NONE;
  case K.ModuleDescriptor:
    this.Printer.p("module descriptor ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.AnonymousDescriptor:
    this.Printer.p("anonymous descriptor ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ExtensionDescriptor:
    this.Printer.p("extension descriptor ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.AssociatedTypeGenericParamRef:
    this.Printer.p("generic parameter reference for associated type ");
    this.printChildren(Node, depth);
    return NONE;
  case K.AnyProtocolConformanceList:
    if (Node.getNumChildren() > 0) {
      this.Printer.p("(");
      for (let i = 0; i < Node.getNumChildren(); ++i) {
        if (i > 0)
          this.Printer.p(", ");
        this.print(Node.getChild(i), depth + 1);
      }
      this.Printer.p(")");
    }
    return NONE;
  case K.ConcreteProtocolConformance:
    this.Printer.p("concrete protocol conformance ");
    if (Node.hasIndex())
      this.Printer.p("#", Node.getIndex(), " ");
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(" to ");
    this.print(Node.getChild(1), depth + 1);
    if (Node.getNumChildren() > 2 &&
        Node.getChild(2).getNumChildren() > 0) {
      this.Printer.p(" with conditional requirements: ");
      this.print(Node.getChild(2), depth + 1);
    }
    return NONE;
  case K.PackProtocolConformance:
    this.Printer.p("pack protocol conformance ");
    this.printChildren(Node, depth);
    return NONE;
  case K.DependentAssociatedConformance:
    this.Printer.p("dependent associated conformance ");
    this.printChildren(Node, depth);
    return NONE;
  case K.DependentProtocolConformanceAssociated:
    this.Printer.p("dependent associated protocol conformance ");
    this.printOptionalIndex(Node.getChild(2));
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(" to ");
    this.print(Node.getChild(1), depth + 1);
    return NONE;
  case K.DependentProtocolConformanceInherited:
    this.Printer.p("dependent inherited protocol conformance ");
    this.printOptionalIndex(Node.getChild(2));
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(" to ");
    this.print(Node.getChild(1), depth + 1);
    return NONE;
  case K.DependentProtocolConformanceRoot:
    this.Printer.p("dependent root protocol conformance ");
    this.printOptionalIndex(Node.getChild(2));
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(" to ");
    this.print(Node.getChild(1), depth + 1);
    return NONE;
  case K.ProtocolConformanceRefInTypeModule:
    this.Printer.p("protocol conformance ref (type's module) ");
    this.printChildren(Node, depth);
    return NONE;
  case K.ProtocolConformanceRefInProtocolModule:
    this.Printer.p("protocol conformance ref (protocol's module) ");
    this.printChildren(Node, depth);
    return NONE;
  case K.ProtocolConformanceRefInOtherModule:
    this.Printer.p("protocol conformance ref (retroactive) ");
    this.printChildren(Node, depth);
    return NONE;
  case K.SugaredOptional:
    this.printWithParens(Node.getChild(0), depth);
    this.Printer.p("?");
    return NONE;
  case K.SugaredArray:
    this.Printer.p("[");
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p("]");
    return NONE;
  case K.SugaredDictionary:
    this.Printer.p("[");
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(" : ");
    this.print(Node.getChild(1), depth + 1);
    this.Printer.p("]");
    return NONE;
  case K.SugaredParen:
    this.Printer.p("(");
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(")");
    return NONE;
  case K.OpaqueReturnType:
    this.Printer.p("some");
    return NONE;
  case K.OpaqueReturnTypeOf:
    this.Printer.p("<<opaque return type of ");
    this.printChildren(Node, depth);
    this.Printer.p(">>");
    return NONE;
  case K.OpaqueType:
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p('.');
    this.print(Node.getChild(1), depth + 1);
    return NONE;
  case K.AccessorFunctionReference:
    this.Printer.p("accessor function at ", Node.getIndex());
    return NONE;
  case K.CanonicalSpecializedGenericMetaclass:
    this.Printer.p("specialized generic metaclass for ");
    this.print(Node.getFirstChild(), depth + 1);
    return NONE;
  case K.CanonicalSpecializedGenericTypeMetadataAccessFunction:
    this.Printer.p("canonical specialized generic type metadata accessor for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.MetadataInstantiationCache:
    this.Printer.p("metadata instantiation cache for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.NoncanonicalSpecializedGenericTypeMetadata:
    this.Printer.p("noncanonical specialized generic type metadata for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.NoncanonicalSpecializedGenericTypeMetadataCache:
    this.Printer.p("cache variable for noncanonical specialized generic type metadata for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.GlobalVariableOnceToken:
  case K.GlobalVariableOnceFunction:
    this.Printer.p((kind == K.GlobalVariableOnceToken
                  ? "one-time initialization token for "
                  : "one-time initialization function for "));
    this.printContext(Node.getChild(0));
    this.print(Node.getChild(1), depth + 1);
    return NONE;
  case K.GlobalVariableOnceDeclList:
    if (Node.getNumChildren() == 1) {
      this.print(Node.getChild(0), depth + 1);
    } else {
      this.Printer.p('(');
      for (let i = 0, e = Node.getNumChildren(); i < e; ++i) {
        if (i != 0) {
          this.Printer.p(", ");
        }
        this.print(Node.getChild(i), depth + 1);
      }
      this.Printer.p(')');
    }
    return NONE;
  case K.PredefinedObjCAsyncCompletionHandlerImpl:
  case K.ObjCAsyncCompletionHandlerImpl:
    if (kind === K.PredefinedObjCAsyncCompletionHandlerImpl) this.Printer.p("predefined ");
    this.Printer.p("@objc completion handler block implementation for ");
    if (Node.getNumChildren() >= 4)
      this.print(Node.getChild(3), depth + 1);
    this.print(Node.getChild(0), depth + 1);
    this.Printer.p(" with result type ");
    this.print(Node.getChild(1), depth + 1);
    switch (Node.getChild(2).getIndex()) {
    case 0:
      break;
    case 1:
      this.Printer.p(" nonzero on error");
      break;
    case 2:
      this.Printer.p(" zero on error");
      break;
    default:
      this.Printer.p(" <invalid error flag>");
      break;
    }
    return NONE;
  case K.CanonicalPrespecializedGenericTypeCachingOnceToken:
    this.Printer.p("flag for loading of canonical specialized generic type " +
               "metadata for ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.AsyncFunctionPointer:
    this.Printer.p("async function pointer to ");
    return NONE;
  case K.AsyncAwaitResumePartialFunction:
    if (this.Options.ShowAsyncResumePartial) {
      this.Printer.p("(");
      this.print(Node.getChild(0), depth + 1);
      this.Printer.p(")");
      this.Printer.p(" await resume partial function for ");
    }
    return NONE;
  case K.AsyncSuspendResumePartialFunction:
    if (this.Options.ShowAsyncResumePartial) {
      this.Printer.p("(");
      this.print(Node.getChild(0), depth + 1);
      this.Printer.p(")");
      this.Printer.p(" suspend resume partial function for ");
    }
    return NONE;
  case K.Uniquable:
    this.Printer.p("uniquable ");
    this.print(Node.getChild(0), depth + 1);
    return NONE;
  case K.ExtendedExistentialTypeShape: {
    // Printing the requirement signature is pretty useless if we
    // don't this.print `where` clauses.
    let savedDisplayWhereClauses = this.Options.DisplayWhereClauses;
    this.Options.DisplayWhereClauses = true;

    let genSig = NONE, type = NONE;
    if (Node.getNumChildren() == 2) {
      genSig = Node.getChild(1);
      type = Node.getChild(2);
    } else {
      type = Node.getChild(1);
    }

    this.Printer.p("existential shape for ");
    if (genSig) {
      this.print(genSig, depth + 1);
      this.Printer.p(" ");
    }
    this.Printer.p("any ");
    this.print(type, depth + 1);

    this.Options.DisplayWhereClauses = savedDisplayWhereClauses;
    return NONE;
  }
  case K.UniqueExtendedExistentialTypeShapeSymbolicReference:
    this.Printer.p("unique existential shape symbolic reference 0x");
    this.Printer.writeHex(Node.getIndex());
    return NONE;
  case K.NonUniqueExtendedExistentialTypeShapeSymbolicReference:
    this.Printer.p("non-unique existential shape symbolic reference 0x");
    this.Printer.writeHex(Node.getIndex());
    return NONE;
  case K.ObjectiveCProtocolSymbolicReference:
    this.Printer.p("objective-c protocol symbolic reference 0x");
    this.Printer.writeHex(Node.getIndex());
    return NONE;
  case K.SymbolicExtendedExistentialType: {
    let shape = Node.getChild(0);
    let isUnique =
      (shape.getKind() ==
         K.UniqueExtendedExistentialTypeShapeSymbolicReference);
    this.Printer.p("symbolic existential type (", (isUnique ? "" : "non-"), "unique) 0x");
    this.Printer.writeHex(shape.getIndex());
    this.Printer.p(" <");
    this.print(Node.getChild(1), depth + 1);
    if (Node.getNumChildren() > 2) {
      this.Printer.p(", ");
      this.print(Node.getChild(2), depth + 1);
    }
    this.Printer.p(">");

    return NONE;
  }
  case K.HasSymbolQuery:
    this.Printer.p("#_hasSymbol query for ");
    return NONE;
  case K.OpaqueReturnTypeIndex:
  case K.OpaqueReturnTypeParent:
    return NONE;
  }

  throw new Error("bad node kind!");
}

  printAbstractStorage(Node: Node, depth: number, asPrefixContent: boolean, ExtraName: string): Node {
  switch (Node.getKind()) {
    case K.Variable:
      return this.printEntity(Node, depth, asPrefixContent, TypePrinting.WithColon,
                         /*hasName*/ true, ExtraName);
    case K.Subscript:
      return this.printEntity(Node, depth, asPrefixContent, TypePrinting.WithColon,
                         /*hasName*/ false, ExtraName, /*ExtraIndex*/ -1,
                         "subscript");
    default:
      throw new Error("Not an abstract storage node");
  }
}

  printEntity(Entity: Node, depth: number, asPrefixContext: boolean, TypePr: TypePrinting, hasName: boolean, ExtraName: string = "", ExtraIndex: number = -1, OverwriteName: string = ""): Node {

  let genericFunctionTypeList = NONE;
  if (Entity.getKind() == K.BoundGenericFunction) {
    genericFunctionTypeList = Entity.getChild(1);
    Entity = Entity.getFirstChild();
  }

  // Either we this.print the context in prefix form "<context>.<name>" or in
  // suffix form "<name> in <context>".
  let MultiWordName = ExtraName.includes(' ');
  // Also a local name (e.g. Mystruct #1) does not look good if its context is
  // printed in prefix form.
  let LocalName =
      hasName && Entity.getChild(1).getKind() == K.LocalDeclName;
  if (LocalName && this.Options.DisplayLocalNameContexts)
    MultiWordName = true;

  if (asPrefixContext && (TypePr != TypePrinting.NoType || MultiWordName)) {
      // If the context has a type to be printed, we can't use the prefix form.
      return Entity;
  }

  let PostfixContext = NONE;
  let Context = Entity.getChild(0);
  if (this.printContext(Context)) {
    if (MultiWordName) {
      // If the name contains some spaces we don't this.print the context now but
      // later in suffix form.
      PostfixContext = Context;
    } else {
      let CurrentPos = this.Printer.s.length;
      PostfixContext = this.print(Context, depth + 1, /*asPrefixContext*/ true);

      // Was the context printed as prefix?
      if (this.Printer.s.length != CurrentPos)
        this.Printer.p('.');
    }
  }

  if (hasName || (OverwriteName.length !== 0)) {
    if ((ExtraName.length !== 0) && MultiWordName) {
      this.Printer.p(ExtraName);
      if (ExtraIndex >= 0)
        this.Printer.p(ExtraIndex);

      this.Printer.p(" of ");
      ExtraName = "";
      ExtraIndex = -1;
    }
    let CurrentPos = this.Printer.s.length;
    if ((OverwriteName.length !== 0)) {
      this.Printer.p(OverwriteName);
    } else {
      let Name = Entity.getChild(1);
      if (Name.getKind() != K.PrivateDeclName)
        this.print(Name, depth + 1);

      const PrivateName = this.getChildIf(Entity, K.PrivateDeclName);
      if (PrivateName)
        this.print(PrivateName, depth + 1);
    }
    if (this.Printer.s.length != CurrentPos && (ExtraName.length !== 0))
      this.Printer.p('.');
  }
  if ((ExtraName.length !== 0)) {
    this.Printer.p(ExtraName);
    if (ExtraIndex >= 0)
      this.Printer.p(ExtraIndex);
  }
  if (TypePr != TypePrinting.NoType) {
    let type = this.getChildIf(Entity, K.Type);
    /* assert */ void 0;
    if (!type) {
      this.setInvalid();
      return NONE;
    }
    type = type.getChild(0);
    if (TypePr == TypePrinting.FunctionStyle) {
      // We expect to see a function type here, but if we don't, use the colon.
      let t = type;
      while (t.getKind() == K.DependentGenericType)
        t = t.getChild(1).getChild(0);
      if (t.getKind() != K.FunctionType &&
          t.getKind() != K.NoEscapeFunctionType &&
          t.getKind() != K.UncurriedFunctionType &&
          t.getKind() != K.CFunctionPointer &&
          t.getKind() != K.ThinFunctionType) {
        TypePr = TypePrinting.WithColon;
      }
    }

    if (TypePr == TypePrinting.WithColon) {
      if (this.Options.DisplayEntityTypes) {
        this.Printer.p(" : ");
        this.printEntityType(Entity, type, genericFunctionTypeList, depth);
      }
    } else if (this.shouldShowEntityType(Entity.getKind(), this.Options)) {
      /* assert */ void 0;
      if (MultiWordName || this.needSpaceBeforeType(type))
        this.Printer.p(' ');
      this.printEntityType(Entity, type, genericFunctionTypeList, depth);
    }
  }
  if (!asPrefixContext && PostfixContext &&
      (!LocalName || this.Options.DisplayLocalNameContexts)) {
    // Print any left over context which couldn't be printed in prefix form.
    if (Entity.getKind() == K.DefaultArgumentInitializer ||
        Entity.getKind() == K.Initializer ||
        Entity.getKind() == K.PropertyWrapperBackingInitializer ||
        Entity.getKind() == K.PropertyWrapperInitFromProjectedValue) {
      this.Printer.p(" of ");
    } else {
      this.Printer.p(" in ");
    }
    this.print(PostfixContext, depth + 1);
    PostfixContext = NONE;
  }
  return PostfixContext;
}

  printEntityType(Entity: Node, type: Node, genericFunctionTypeList: Node, depth: number): void {
  let labelList = this.getChildIf(Entity, K.LabelList);
  if (labelList || genericFunctionTypeList) {
    if (genericFunctionTypeList) {
      this.Printer.p("<");
      this.printChildren(genericFunctionTypeList, depth, ", ");
      this.Printer.p(">");
    }
    if (type.getKind() == K.DependentGenericType) {
      if (!genericFunctionTypeList)
        this.print(type.getChild(0), depth + 1); // generic signature

      let dependentType = type.getChild(1);
      if (this.needSpaceBeforeType(dependentType))
        this.Printer.p(' ');
      type = dependentType.getFirstChild();
    }
    this.printFunctionType(labelList, type, depth);
  } else {
    this.print(type, depth + 1);
  }
}

}
