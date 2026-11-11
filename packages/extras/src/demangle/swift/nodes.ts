// Swift demangler node tree. Ported from the Swift project (lib/Demangling, include/swift/Demangling,
// swift-6.0.3-RELEASE), Copyright (c) 2014-2024 Apple Inc. and the Swift project authors,
// licensed under the Apache License v2.0 with Runtime Library Exception. See README for credit.

/* eslint-disable */
export const KIND_NAMES = ['Allocator', 'AnonymousContext', 'AnyProtocolConformanceList', 'ArgumentTuple', 'AssociatedType', 'AssociatedTypeRef', 'AssociatedTypeMetadataAccessor', 'DefaultAssociatedTypeMetadataAccessor', 'AccessorAttachedMacroExpansion', 'AssociatedTypeWitnessTableAccessor', 'BaseWitnessTableAccessor', 'AutoClosureType', 'BodyAttachedMacroExpansion', 'BoundGenericClass', 'BoundGenericEnum', 'BoundGenericStructure', 'BoundGenericProtocol', 'BoundGenericOtherNominalType', 'BoundGenericTypeAlias', 'BoundGenericFunction', 'BuiltinTypeName', 'BuiltinTupleType', 'CFunctionPointer', 'ClangType', 'Class', 'ClassMetadataBaseOffset', 'ConcreteProtocolConformance', 'PackProtocolConformance', 'ConformanceAttachedMacroExpansion', 'Constructor', 'CoroutineContinuationPrototype', 'Deallocator', 'DeclContext', 'DefaultArgumentInitializer', 'DependentAssociatedConformance', 'DependentAssociatedTypeRef', 'DependentGenericConformanceRequirement', 'DependentGenericParamCount', 'DependentGenericParamType', 'DependentGenericSameTypeRequirement', 'DependentGenericSameShapeRequirement', 'DependentGenericLayoutRequirement', 'DependentGenericParamPackMarker', 'DependentGenericSignature', 'DependentGenericType', 'DependentMemberType', 'DependentPseudogenericSignature', 'DependentProtocolConformanceRoot', 'DependentProtocolConformanceInherited', 'DependentProtocolConformanceAssociated', 'Destructor', 'DidSet', 'Directness', 'DistributedThunk', 'DistributedAccessor', 'DynamicAttribute', 'DirectMethodReferenceAttribute', 'DynamicSelf', 'DynamicallyReplaceableFunctionImpl', 'DynamicallyReplaceableFunctionKey', 'DynamicallyReplaceableFunctionVar', 'Enum', 'EnumCase', 'ErrorType', 'EscapingAutoClosureType', 'NoEscapeFunctionType', 'ConcurrentFunctionType', 'GlobalActorFunctionType', 'DifferentiableFunctionType', 'ExistentialMetatype', 'ExplicitClosure', 'Extension', 'ExtensionAttachedMacroExpansion', 'FieldOffset', 'FreestandingMacroExpansion', 'FullTypeMetadata', 'Function', 'FunctionSignatureSpecialization', 'FunctionSignatureSpecializationParam', 'FunctionSignatureSpecializationReturn', 'FunctionSignatureSpecializationParamKind', 'FunctionSignatureSpecializationParamPayload', 'FunctionType', 'ConstrainedExistential', 'ConstrainedExistentialRequirementList', 'ConstrainedExistentialSelf', 'GenericPartialSpecialization', 'GenericPartialSpecializationNotReAbstracted', 'GenericProtocolWitnessTable', 'GenericProtocolWitnessTableInstantiationFunction', 'ResilientProtocolWitnessTable', 'GenericSpecialization', 'GenericSpecializationNotReAbstracted', 'GenericSpecializationInResilienceDomain', 'GenericSpecializationParam', 'GenericSpecializationPrespecialized', 'InlinedGenericFunction', 'GenericTypeMetadataPattern', 'Getter', 'Global', 'GlobalGetter', 'Identifier', 'Index', 'IVarInitializer', 'IVarDestroyer', 'ImplEscaping', 'ImplConvention', 'ImplDifferentiabilityKind', 'ImplErasedIsolation', 'ImplSendingResult', 'ImplParameterResultDifferentiability', 'ImplParameterSending', 'ImplFunctionAttribute', 'ImplFunctionConvention', 'ImplFunctionConventionName', 'ImplFunctionType', 'ImplInvocationSubstitutions', 'ImplicitClosure', 'ImplParameter', 'ImplPatternSubstitutions', 'ImplResult', 'ImplYield', 'ImplErrorResult', 'InOut', 'InfixOperator', 'Initializer', 'InitAccessor', 'Isolated', 'Sending', 'IsolatedAnyFunctionType', 'SendingResultFunctionType', 'KeyPathGetterThunkHelper', 'KeyPathSetterThunkHelper', 'KeyPathEqualsThunkHelper', 'KeyPathHashThunkHelper', 'LazyProtocolWitnessTableAccessor', 'LazyProtocolWitnessTableCacheVariable', 'LocalDeclName', 'Macro', 'MacroExpansionLoc', 'MacroExpansionUniqueName', 'MaterializeForSet', 'MemberAttachedMacroExpansion', 'MemberAttributeAttachedMacroExpansion', 'MergedFunction', 'Metatype', 'MetatypeRepresentation', 'Metaclass', 'MethodLookupFunction', 'ObjCMetadataUpdateFunction', 'ObjCResilientClassStub', 'FullObjCResilientClassStub', 'ModifyAccessor', 'Module', 'NativeOwningAddressor', 'NativeOwningMutableAddressor', 'NativePinningAddressor', 'NativePinningMutableAddressor', 'NominalTypeDescriptor', 'NominalTypeDescriptorRecord', 'NonObjCAttribute', 'Number', 'ObjCAsyncCompletionHandlerImpl', 'PredefinedObjCAsyncCompletionHandlerImpl', 'ObjCAttribute', 'ObjCBlock', 'EscapingObjCBlock', 'OtherNominalType', 'OwningAddressor', 'OwningMutableAddressor', 'PartialApplyForwarder', 'PartialApplyObjCForwarder', 'PeerAttachedMacroExpansion', 'PostfixOperator', 'PreambleAttachedMacroExpansion', 'PrefixOperator', 'PrivateDeclName', 'PropertyDescriptor', 'PropertyWrapperBackingInitializer', 'PropertyWrapperInitFromProjectedValue', 'Protocol', 'ProtocolSymbolicReference', 'ProtocolConformance', 'ProtocolConformanceRefInTypeModule', 'ProtocolConformanceRefInProtocolModule', 'ProtocolConformanceRefInOtherModule', 'ProtocolDescriptor', 'ProtocolDescriptorRecord', 'ProtocolConformanceDescriptor', 'ProtocolConformanceDescriptorRecord', 'ProtocolList', 'ProtocolListWithClass', 'ProtocolListWithAnyObject', 'ProtocolSelfConformanceDescriptor', 'ProtocolSelfConformanceWitness', 'ProtocolSelfConformanceWitnessTable', 'ProtocolWitness', 'ProtocolWitnessTable', 'ProtocolWitnessTableAccessor', 'ProtocolWitnessTablePattern', 'ReabstractionThunk', 'ReabstractionThunkHelper', 'ReabstractionThunkHelperWithSelf', 'ReabstractionThunkHelperWithGlobalActor', 'ReadAccessor', 'RelatedEntityDeclName', 'RetroactiveConformance', 'ReturnType', 'Shared', 'Owned', 'SILBoxType', 'SILBoxTypeWithLayout', 'SILBoxLayout', 'SILBoxMutableField', 'SILBoxImmutableField', 'Setter', 'SpecializationPassID', 'IsSerialized', 'Static', 'Structure', 'Subscript', 'Suffix', 'ThinFunctionType', 'Tuple', 'TupleElement', 'TupleElementName', 'Pack', 'SILPackDirect', 'SILPackIndirect', 'PackExpansion', 'PackElement', 'PackElementLevel', 'Type', 'TypeSymbolicReference', 'TypeAlias', 'TypeList', 'TypeMangling', 'TypeMetadata', 'TypeMetadataAccessFunction', 'TypeMetadataCompletionFunction', 'TypeMetadataInstantiationCache', 'TypeMetadataInstantiationFunction', 'TypeMetadataSingletonInitializationCache', 'TypeMetadataDemanglingCache', 'TypeMetadataLazyCache', 'UncurriedFunctionType', 'UnknownIndex', 'UnsafeAddressor', 'UnsafeMutableAddressor', 'ValueWitness', 'ValueWitnessTable', 'Variable', 'VTableThunk', 'VTableAttribute', 'WillSet', 'ReflectionMetadataBuiltinDescriptor', 'ReflectionMetadataFieldDescriptor', 'ReflectionMetadataAssocTypeDescriptor', 'ReflectionMetadataSuperclassDescriptor', 'GenericTypeParamDecl', 'CurryThunk', 'DispatchThunk', 'MethodDescriptor', 'ProtocolRequirementsBaseDescriptor', 'AssociatedConformanceDescriptor', 'DefaultAssociatedConformanceAccessor', 'BaseConformanceDescriptor', 'AssociatedTypeDescriptor', 'AsyncAnnotation', 'ThrowsAnnotation', 'TypedThrowsAnnotation', 'EmptyList', 'FirstElementMarker', 'VariadicMarker', 'OutlinedBridgedMethod', 'OutlinedCopy', 'OutlinedConsume', 'OutlinedRetain', 'OutlinedRelease', 'OutlinedInitializeWithTake', 'OutlinedInitializeWithCopy', 'OutlinedAssignWithTake', 'OutlinedAssignWithCopy', 'OutlinedDestroy', 'OutlinedVariable', 'OutlinedReadOnlyObject', 'AssocTypePath', 'LabelList', 'ModuleDescriptor', 'ExtensionDescriptor', 'AnonymousDescriptor', 'AssociatedTypeGenericParamRef', 'SugaredOptional', 'SugaredArray', 'SugaredDictionary', 'SugaredParen', 'AccessorFunctionReference', 'OpaqueType', 'OpaqueTypeDescriptorSymbolicReference', 'OpaqueTypeDescriptor', 'OpaqueTypeDescriptorRecord', 'OpaqueTypeDescriptorAccessor', 'OpaqueTypeDescriptorAccessorImpl', 'OpaqueTypeDescriptorAccessorKey', 'OpaqueTypeDescriptorAccessorVar', 'OpaqueReturnType', 'OpaqueReturnTypeOf', 'CanonicalSpecializedGenericMetaclass', 'CanonicalSpecializedGenericTypeMetadataAccessFunction', 'MetadataInstantiationCache', 'NoncanonicalSpecializedGenericTypeMetadata', 'NoncanonicalSpecializedGenericTypeMetadataCache', 'GlobalVariableOnceFunction', 'GlobalVariableOnceToken', 'GlobalVariableOnceDeclList', 'CanonicalPrespecializedGenericTypeCachingOnceToken', 'AsyncFunctionPointer', 'AutoDiffFunction', 'AutoDiffFunctionKind', 'AutoDiffSelfReorderingReabstractionThunk', 'AutoDiffSubsetParametersThunk', 'AutoDiffDerivativeVTableThunk', 'DifferentiabilityWitness', 'NoDerivative', 'IndexSubset', 'AsyncAwaitResumePartialFunction', 'AsyncSuspendResumePartialFunction', 'AccessibleFunctionRecord', 'CompileTimeConst', 'BackDeploymentThunk', 'BackDeploymentFallback', 'ExtendedExistentialTypeShape', 'Uniquable', 'UniqueExtendedExistentialTypeShapeSymbolicReference', 'NonUniqueExtendedExistentialTypeShapeSymbolicReference', 'SymbolicExtendedExistentialType', 'MetatypeParamsRemoved', 'HasSymbolQuery', 'OpaqueReturnTypeIndex', 'OpaqueReturnTypeParent', 'OutlinedEnumTagStore', 'OutlinedEnumProjectDataForLoad', 'OutlinedEnumGetTag', 'AsyncRemoved', 'ObjectiveCProtocolSymbolicReference', 'ParamLifetimeDependence', 'SelfLifetimeDependence', 'OutlinedInitializeWithCopyNoValueWitness', 'OutlinedAssignWithTakeNoValueWitness', 'OutlinedAssignWithCopyNoValueWitness', 'OutlinedDestroyNoValueWitness', 'DependentGenericInverseConformanceRequirement', 'Weak', 'Unowned', 'Unmanaged'] as const;
export type Kind = (typeof KIND_NAMES)[number];
export const K: { readonly [P in Kind]: P } = Object.fromEntries(KIND_NAMES.map((n) => [n, n])) as never;
const CONTEXT_KINDS = new Set<string>(['Allocator', 'AnonymousContext', 'Class', 'Constructor', 'Deallocator', 'DefaultArgumentInitializer', 'Destructor', 'DidSet', 'Enum', 'ExplicitClosure', 'Extension', 'Function', 'Getter', 'GlobalGetter', 'IVarInitializer', 'IVarDestroyer', 'ImplicitClosure', 'Initializer', 'InitAccessor', 'MaterializeForSet', 'ModifyAccessor', 'Module', 'NativeOwningAddressor', 'NativeOwningMutableAddressor', 'NativePinningAddressor', 'NativePinningMutableAddressor', 'OtherNominalType', 'OwningAddressor', 'OwningMutableAddressor', 'PropertyWrapperBackingInitializer', 'PropertyWrapperInitFromProjectedValue', 'Protocol', 'ProtocolSymbolicReference', 'ReadAccessor', 'Setter', 'Static', 'Structure', 'Subscript', 'TypeSymbolicReference', 'TypeAlias', 'UnsafeAddressor', 'UnsafeMutableAddressor', 'Variable', 'WillSet', 'OpaqueReturnTypeOf', 'AutoDiffFunction']);

/** One node of a demangled Swift symbol tree. */
export class Node {
  text?: string;
  index?: number;
  children: Node[] = [];
  constructor(public kind: Kind, payload?: string | number) {
    if (typeof payload === 'string') this.text = payload;
    else if (typeof payload === 'number') this.index = payload;
  }
  getKind(): Kind { return this.kind; }
  hasText(): boolean { return this.text !== undefined; }
  getText(): string { return this.text ?? ''; }
  hasIndex(): boolean { return this.index !== undefined; }
  getIndex(): number { return this.index ?? 0; }
  getNumChildren(): number { return this.children.length; }
  hasChildren(): boolean { return this.children.length !== 0; }
  getChild(i: number): Node { return this.children[i] ?? NONE; }
  getFirstChild(): Node { return this.getChild(0); }
  getLastChild(): Node { return this.getChild(this.children.length - 1); }
  addChild(c: Node, _f?: unknown): void {
    if (!c) throw new DemangleError('null child');
    if (this.text !== undefined || this.index !== undefined) throw new DemangleError('cannot add child to a leaf node');
    if (this.children.length >= 4096) throw new DemangleError('too many children');
    this.children.push(c);
  }
  removeChildAt(i: number): void { this.children.splice(i, 1); }
  replaceChild(i: number, c: Node): void { if (i < this.children.length) this.children[i] = c; }
  reverseChildren(from = 0): void { const t = this.children.splice(from).reverse(); this.children.push(...t); }
  findByKind(kind: Kind, maxDepth: number): Node {
    if (this.kind === kind) return this;
    if (maxDepth <= 0) return NONE;
    for (const n of this.children) { const m = n.findByKind(kind, maxDepth - 1); if (m) return m; }
    return NONE;
  }
  isSimilarTo(o: Node): boolean { return this.kind === o.kind && this.text === o.text && this.index === o.index && this.children.length === o.children.length; }
}

/** Typed stand-in for a null node pointer, so the ported code can test `if (!n)` like the C++ does. */
export const NONE = null as unknown as Node;

export class DemangleError extends Error {}

export function isContext(kind: Kind): boolean { return CONTEXT_KINDS.has(kind) || kind === 'BuiltinTupleType'; }

export const isLowerLetter = (c: string): boolean => c >= 'a' && c <= 'z' && c.length === 1;
export const isUpperLetter = (c: string): boolean => c >= 'A' && c <= 'Z' && c.length === 1;
export const isDigit = (c: string): boolean => c >= '0' && c <= '9' && c.length === 1;
export const isLetter = (c: string): boolean => isLowerLetter(c) || isUpperLetter(c);
export const isWordStart = (c: string): boolean => !isDigit(c) && c !== '_' && c !== '\0';
export const isWordEnd = (c: string, prev: string): boolean => c === '_' || c === '\0' || (!isUpperLetter(prev) && isUpperLetter(c));
export const charCode = (c: string): number => c.charCodeAt(0) || 0;

export enum FunctionSigSpecializationParamKind {
  ConstantPropFunction = 0, ConstantPropGlobal = 1, ConstantPropInteger = 2, ConstantPropFloat = 3, ConstantPropString = 4,
  ClosureProp = 5, BoxToValue = 6, BoxToStack = 7, InOutToOut = 8, ConstantPropKeyPath = 9,
  Dead = 1 << 6, OwnedToGuaranteed = 1 << 7, SROA = 1 << 8, GuaranteedToOwned = 1 << 9, ExistentialToGeneric = 1 << 10,
}
export enum MangledDifferentiabilityKind { NonDifferentiable = '\0', Forward = 'f', Reverse = 'r', Normal = 'd', Linear = 'l' }
export enum AutoDiffFunctionKind { JVP = 'f', VJP = 'r', Differential = 'd', Pullback = 'p' }
export enum MangledLifetimeDependenceKind { Inherit = 'i', Scope = 's' }
export enum Directness { Direct, Indirect }
export const VALUE_WITNESSES: [string, string][] = [
  ['al', 'AllocateBuffer'], ['ca', 'AssignWithCopy'], ['ta', 'AssignWithTake'], ['de', 'DeallocateBuffer'], ['xx', 'Destroy'],
  ['XX', 'DestroyBuffer'], ['Xx', 'DestroyArray'], ['CP', 'InitializeBufferWithCopyOfBuffer'], ['Cp', 'InitializeBufferWithCopy'],
  ['cp', 'InitializeWithCopy'], ['Tk', 'InitializeBufferWithTake'], ['tk', 'InitializeWithTake'], ['pr', 'ProjectBuffer'],
  ['TK', 'InitializeBufferWithTakeOfBuffer'], ['Cc', 'InitializeArrayWithCopy'], ['Tt', 'InitializeArrayWithTakeFrontToBack'],
  ['tT', 'InitializeArrayWithTakeBackToFront'], ['xs', 'StoreExtraInhabitant'], ['xg', 'GetExtraInhabitantIndex'], ['ug', 'GetEnumTag'],
  ['up', 'DestructiveProjectEnumData'], ['ui', 'DestructiveInjectEnumTag'], ['et', 'GetEnumTagSinglePayload'], ['st', 'StoreEnumTagSinglePayload'],
];
export const STDLIB_NAME = 'Swift';
export const MANGLING_MODULE_OBJC = '__C';
export const MANGLING_MODULE_CLANG_IMPORTER = '__C_Synthesized';
export const BUILTIN_TYPE_NAME_PREFIX = 'Builtin.';
export const LLDB_EXPRESSIONS_MODULE_NAME_PREFIX = '__lldb_expr_';

/** Generic parameter name for depth and index: A, B, ... Z, A1 ... and a depth suffix. */
export function genericParameterName(depth: number, index: number): string {
  let name = '';
  do { name += String.fromCharCode(65 + (index % 26)); index = Math.floor(index / 26); } while (index);
  if (depth !== 0) name += String(depth);
  return name;
}
export const BUILTIN_TYPE_NAME_INT = 'Builtin.Int';
export const BUILTIN_TYPE_NAME_INT8 = 'Builtin.Int8';
export const BUILTIN_TYPE_NAME_INT16 = 'Builtin.Int16';
export const BUILTIN_TYPE_NAME_INT32 = 'Builtin.Int32';
export const BUILTIN_TYPE_NAME_INT64 = 'Builtin.Int64';
export const BUILTIN_TYPE_NAME_INT128 = 'Builtin.Int128';
export const BUILTIN_TYPE_NAME_INT256 = 'Builtin.Int256';
export const BUILTIN_TYPE_NAME_INT512 = 'Builtin.Int512';
export const BUILTIN_TYPE_NAME_INTLITERAL = 'Builtin.IntLiteral';
export const BUILTIN_TYPE_NAME_FLOAT = 'Builtin.FPIEEE';
export const BUILTIN_TYPE_NAME_FLOAT_PPC = 'Builtin.FPPPC';
export const BUILTIN_TYPE_NAME_NATIVEOBJECT = 'Builtin.NativeObject';
export const BUILTIN_TYPE_NAME_BRIDGEOBJECT = 'Builtin.BridgeObject';
export const BUILTIN_TYPE_NAME_RAWPOINTER = 'Builtin.RawPointer';
export const BUILTIN_TYPE_NAME_RAWUNSAFECONTINUATION = 'Builtin.RawUnsafeContinuation';
export const BUILTIN_TYPE_NAME_UNSAFEVALUEBUFFER = 'Builtin.UnsafeValueBuffer';
export const BUILTIN_TYPE_NAME_JOB = 'Builtin.Job';
export const BUILTIN_TYPE_NAME_EXECUTOR = 'Builtin.Executor';
export const BUILTIN_TYPE_NAME_DEFAULTACTORSTORAGE = 'Builtin.DefaultActorStorage';
export const BUILTIN_TYPE_NAME_NONDEFAULTDISTRIBUTEDACTORSTORAGE = 'Builtin.NonDefaultDistributedActorStorage';
export const BUILTIN_TYPE_NAME_UNKNOWNOBJECT = 'Builtin.UnknownObject';
export const BUILTIN_TYPE_NAME_VEC = 'Builtin.Vec';
export const BUILTIN_TYPE_NAME_SILTOKEN = 'Builtin.SILToken';
export const BUILTIN_TYPE_NAME_WORD = 'Builtin.Word';
export const BUILTIN_TYPE_NAME_PACKINDEX = 'Builtin.PackIndex';
export const STANDARD_TYPES: Record<string, [Kind, string]> = {A: ['Structure', 'AutoreleasingUnsafeMutablePointer'], a: ['Structure', 'Array'], b: ['Structure', 'Bool'], D: ['Structure', 'Dictionary'], d: ['Structure', 'Double'], f: ['Structure', 'Float'], h: ['Structure', 'Set'], I: ['Structure', 'DefaultIndices'], i: ['Structure', 'Int'], J: ['Structure', 'Character'], N: ['Structure', 'ClosedRange'], n: ['Structure', 'Range'], O: ['Structure', 'ObjectIdentifier'], P: ['Structure', 'UnsafePointer'], p: ['Structure', 'UnsafeMutablePointer'], R: ['Structure', 'UnsafeBufferPointer'], r: ['Structure', 'UnsafeMutableBufferPointer'], S: ['Structure', 'String'], s: ['Structure', 'Substring'], u: ['Structure', 'UInt'], V: ['Structure', 'UnsafeRawPointer'], v: ['Structure', 'UnsafeMutableRawPointer'], W: ['Structure', 'UnsafeRawBufferPointer'], w: ['Structure', 'UnsafeMutableRawBufferPointer'], q: ['Enum', 'Optional'], B: ['Protocol', 'BinaryFloatingPoint'], E: ['Protocol', 'Encodable'], e: ['Protocol', 'Decodable'], F: ['Protocol', 'FloatingPoint'], G: ['Protocol', 'RandomNumberGenerator'], H: ['Protocol', 'Hashable'], j: ['Protocol', 'Numeric'], K: ['Protocol', 'BidirectionalCollection'], k: ['Protocol', 'RandomAccessCollection'], L: ['Protocol', 'Comparable'], l: ['Protocol', 'Collection'], M: ['Protocol', 'MutableCollection'], m: ['Protocol', 'RangeReplaceableCollection'], Q: ['Protocol', 'Equatable'], T: ['Protocol', 'Sequence'], t: ['Protocol', 'IteratorProtocol'], U: ['Protocol', 'UnsignedInteger'], X: ['Protocol', 'RangeExpression'], x: ['Protocol', 'Strideable'], Y: ['Protocol', 'RawRepresentable'], y: ['Protocol', 'StringProtocol'], Z: ['Protocol', 'SignedInteger'], z: ['Protocol', 'BinaryInteger']};
export const STANDARD_TYPES_CONCURRENCY: Record<string, [Kind, string]> = {A: ['Protocol', 'Actor'], C: ['Structure', 'CheckedContinuation'], c: ['Structure', 'UnsafeContinuation'], E: ['Structure', 'CancellationError'], e: ['Structure', 'UnownedSerialExecutor'], F: ['Protocol', 'Executor'], f: ['Protocol', 'SerialExecutor'], G: ['Structure', 'TaskGroup'], g: ['Structure', 'ThrowingTaskGroup'], h: ['Protocol', 'TaskExecutor'], I: ['Protocol', 'AsyncIteratorProtocol'], i: ['Protocol', 'AsyncSequence'], J: ['Structure', 'UnownedJob'], M: ['Class', 'MainActor'], P: ['Structure', 'TaskPriority'], S: ['Structure', 'AsyncStream'], s: ['Structure', 'AsyncThrowingStream'], T: ['Structure', 'Task'], t: ['Structure', 'UnsafeCurrentTask']};
