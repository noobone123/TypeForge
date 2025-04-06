package typeforge.analyzer;

import ghidra.program.model.data.Structure;
import typeforge.base.dataflow.Range;
import typeforge.base.dataflow.expression.NMAE;
import typeforge.base.dataflow.expression.NMAEManager;
import typeforge.base.dataflow.constraint.TypeConstraint;
import typeforge.base.dataflow.solver.TypeHintCollector;
import typeforge.base.passes.SlidingWindowProcessor;
import typeforge.utils.DataTypeHelper;
import typeforge.utils.Global;
import typeforge.utils.Logging;
import ghidra.program.model.data.DataType;

import java.util.*;

/**
 * This Class should create a set of Structure Builder for each SymbolExpr, and can be used to import into Ghidra.
 * Each DataType Constraints has a member named associatedExpr, which can be used to get the function which uses this DataType.
 *
 * So the Generator should be able to output:
 * 1. A set of Structure Builder for each HighSymbol. (Or one specified HighSymbol in Testing or Practice)
 * 2. A set of Function and its HighSymbol which uses this DataType.
 *
 * Next, above information can be taken as input to the DataType Importer component.
 * DataType Importer will create retype HighSymbols for each Structure Builder and get each Function's updated pseudocode.
 * Retype process should be done from callee to caller, which can utilize.
 * result: {
 *     "StructureBuilder_1": [pseudo_code_1, pseudo_code_2, ...],
 *     "StructureBuilder_2": [pseudo_code_3, pseudo_code_4, ...],
 *     ...
 * }
 * Finally, We take the pseudocode and Calculate the score for them, and find the best one as the final Structure Type
 */
public class Generator {
    public TypeHintCollector typeHintCollector;
    public NMAEManager exprManager;
    private final Set<TypeConstraint> finalTypeConstraints;


    public Generator(TypeHintCollector typeHintCollector, NMAEManager exprManager) {
        this.typeHintCollector = typeHintCollector;
        this.exprManager = exprManager;
        this.finalTypeConstraints = new HashSet<>();
    }

    public Set<TypeConstraint> getFinalSkeletons() {
        return finalTypeConstraints;
    }

    public Map<NMAE, TypeConstraint> getExprToSkeletonMap() {
        var exprToSkeletonMap = new HashMap<NMAE, TypeConstraint>();
        for (var entry: typeHintCollector.exprToConstraintMap.entrySet()) {
            var expr = entry.getKey();
            var skt = entry.getValue();
            if (finalTypeConstraints.contains(skt)) {
                exprToSkeletonMap.put(expr, skt);
            }
        }
        return exprToSkeletonMap;
    }

    /**
     * Generate all possible structure declarations for each skeleton.
     */
    public void run() {
        /* Generation Morphing Types */
        generation();

        /* Post Processing: remove redundant type declaration in morph range */
        for (var c: finalTypeConstraints) {
            if (c.isMultiLevelMidPtr || c.isPointerToPrimitive) {
                continue;
            }
            if (c.noMorphingTypes() && c.finalType != null) {
                Logging.debug("Generator", "Found Stable Constraint with Final Type");
            } else {
                Logging.debug("Generator", "Found Unstable Constraint with Morphing Types");
                // Removing redundant composite type declaration with different name
                for (var entry: new HashMap<>(c.rangeMorphingTypes).entrySet()) {
                    var range = entry.getKey();
                    var morphingTypes = entry.getValue();
                    Map<Integer, DataType> layoutHashToDT = new HashMap<>();
                    for (var morphingType: morphingTypes) {
                        var layoutHash = DataTypeHelper.calculateLayoutHash((Structure) morphingType);
                        if (layoutHashToDT.containsKey(layoutHash)) {
                            Logging.debug("Generator", "Found Same Type Declaration with Different Name");
                        } else {
                            layoutHashToDT.put(layoutHash, morphingType);
                        }
                    }
                    c.rangeMorphingTypes.put(range, new HashSet<>(layoutHashToDT.values()));
                }
            }
        }
    }


    // TODO: populate empty (not padding) intervals with char[]
    // TODO: utilize ghidra structure's auto undefined filler.
    // TODO: handle Evil Sources, Evil Nodes and Evil Paths
    private void generation() {
        var exprToConstraintMap = typeHintCollector.exprToConstraintMap;

        for (var c: new HashSet<>(exprToConstraintMap.values())) {
            if (c.innerSkeleton.isEmpty()) {
                continue;
            }
            if (c.isMultiLevelMidPtr || c.isPointerToPrimitive) {
                continue;
            }
            if (c.mayPointerToPrimitiveArray) {
                handleMayPrimitiveArray(c);
                continue;
            }
            processFieldMorphing(c);
        }

        for (var c: new HashSet<>(exprToConstraintMap.values())) {
            if (c.innerSkeleton.isEmpty()) {
                continue;
            }
            if (c.isMultiLevelMidPtr || c.isPointerToPrimitive) {
                continue;
            }
            /* These Stable Types have no nested skeletons and no Incosistency and Primitive Flatten */
            if (c.noMorphingTypes() && c.finalType == null) {
                handleNoMorphingSkeleton(c);
            }
            finalTypeConstraints.add(c);
        }
    }

    private void processFieldMorphing(TypeConstraint c) {
        handleInconsistencyField(c);
        handleComplexFlatten(c);
        handlePrimitiveFlatten(c);
    }

    private void handleNoMorphingSkeleton(TypeConstraint c) {
        var componentMap = getComponentMapByMostAccessed(c);
        c.finalType = DataTypeHelper.createUniqueStructure(c, componentMap);
    }

    private void handleMayPrimitiveArray(TypeConstraint constraint) {
        var aps = constraint.innerSkeleton.fieldAccess.get(0L);
        if (aps == null) { return; }
        var elementType = aps.mostAccessedDT;

        var componentMap = getComponentMapByMostAccessed(constraint);
        var structDT = DataTypeHelper.createUniqueStructure(constraint, componentMap);
        constraint.updateGlobalMorphingDataType(elementType);
        constraint.updateGlobalMorphingDataType(structDT);
    }

    private void handleInconsistencyField(TypeConstraint c) {
        for (var entry: c.innerSkeleton.fieldAccess.entrySet()) {
            var offset = entry.getKey();
            var aps = entry.getValue();

            if (c.hasFinalNestedConstraint() && c.isInNestedRange(offset)) {
                continue;
            }

            if (!aps.isSameSizeType && !c.finalPtrReference.containsKey(offset)) {
                Logging.debug("Generator", String.format("Inconsistency Field: Offset = 0x%s", Long.toHexString(offset)));
                c.markInconsistentOffset(offset);

                // Create Union or Find the most accessed data type
                var componentMap_u = getComponentMapByUnionFields(c, offset);
                var structDT_u = DataTypeHelper.createUniqueStructure(c, componentMap_u);
                var DTs = new HashSet<DataType>(Set.of(structDT_u));

                /* create unique structure for each different member size */
                var typeSizes = new HashSet<Integer>(aps.mostAccessedDT.getLength());
                for (var dt: aps.allDTs) {
                    if (typeSizes.contains(dt.getLength())) { continue; }
                    var componentMap = getComponentMapBySpecifyDT(c, offset, dt);
                    var structDT = DataTypeHelper.createUniqueStructure(c, componentMap);
                    DTs.add(structDT);
                    typeSizes.add(dt.getLength());
                }

                c.updateRangeMorphingDataType(offset, offset + aps.maxDTSize, DTs);
            }
        }
    }

    private void handlePrimitiveFlatten(TypeConstraint constraint) {
        List<Long> offsets = new ArrayList<>(constraint.innerSkeleton.fieldAccess.keySet());
        SlidingWindowProcessor windowProcessor = new SlidingWindowProcessor(constraint, offsets, 1);

        for (int i = 0; i < offsets.size() - 1; i++) {
            var curOffset = offsets.get(i);
            if (Global.currentProgram.getDefaultPointerSize() > 0
                    && curOffset % Global.currentProgram.getDefaultPointerSize() != 0) {
                continue;
            }

            var hasFlattenWindow = windowProcessor.tryMatchingFromCurrentOffset(i, 4);
            if (hasFlattenWindow.isEmpty()) { continue; }

            var window = hasFlattenWindow.get();
            DataType winDT = window.getWindowDT();
            int flattenCnt = windowProcessor.getFlattenCount();

            var componentMap_1 = getComponentMapByMostAccessed(constraint);
            var structDT_1 = DataTypeHelper.createUniqueStructure(constraint, componentMap_1);

            var componentMap_2 = getComponentMapByRecoverFlattenToArray(constraint, curOffset, winDT, flattenCnt);
            var structDT_2 = DataTypeHelper.createUniqueStructure(constraint, componentMap_2);

            var startOffset = offsets.get(i).intValue();
            var endOffset = startOffset + window.getAlignedWindowSize() * flattenCnt;
            constraint.updateRangeMorphingDataType(startOffset, endOffset, new HashSet<>(Set.of(structDT_1, structDT_2)));

            Logging.debug("Generator",
                    String.format("Found a match of primitive flatten from offset 0x%x with %d count", curOffset, flattenCnt));
            Logging.debug("Generator",
                    String.format("Window's DataType:\n%s", winDT));

            windowProcessor.resetFlattenCnt();
        }
    }

    private void handleComplexFlatten(TypeConstraint c) {
        List<Long> offsets = new ArrayList<>(c.innerSkeleton.fieldAccess.keySet());
        SlidingWindowProcessor windowProcessor = new SlidingWindowProcessor(c, offsets, 2);

        /* same window should not appear twice in the same range */
        Map<Integer, Set<Range>> winDTHashToRanges = new HashMap<>();
        for (int i = 0; i < offsets.size() - 1; i++) {
            var offset = offsets.get(i);
            if (Global.currentProgram.getDefaultPointerSize() > 0
                    && offset % Global.currentProgram.getDefaultPointerSize() != 0) {
                continue;
            }
            for (int capacity = 2; ((offsets.size() - i) / capacity) >= 2; capacity ++) {
                windowProcessor.setWindowCapacity(capacity);
                var hasFlattenWindow = windowProcessor.tryMatchingFromCurrentOffset(i, 3);
                if (hasFlattenWindow.isEmpty()) { continue; }

                var window = hasFlattenWindow.get();
                DataType winDT = window.getWindowDT();
                int winDTHash = DataTypeHelper.calculateLayoutHash((Structure) winDT);
                int flattenCnt = windowProcessor.getFlattenCount();
                var nestStartOffset = offsets.get(i);
                var nestEndOffset = nestStartOffset + (long) winDT.getLength() * flattenCnt;
                var range = new Range(nestStartOffset, nestEndOffset);
                if (!winDTHashToRanges.containsKey(winDTHash)) {
                    winDTHashToRanges.put(winDTHash, new HashSet<>(Set.of(range)));
                } else {
                    var existRanges = winDTHashToRanges.get(winDTHash);
                    if (Range.ifRangeInRanges(range, existRanges)) {
                        Logging.debug("Generator", "Found a duplicate window in the same range");
                        continue;
                    } else {
                        existRanges.add(range);
                    }
                }

                var componentMap_1 = getComponentMapByMostAccessed(c);
                var structDT_1 = DataTypeHelper.createUniqueStructure(c, componentMap_1);
                // var componentMap_2 = getComponentMapByRecoverFlattenToArray(skt, offsets.get(i), winDT, flattenCnt);
                // var structDT_2 = DataTypeHelper.createUniqueStructure(skt, componentMap_2);
                var componentMap_3 = getComponentMapByRecoverFlattenToNest(c, offsets.get(i), winDT, flattenCnt);
                var structDT_3 = DataTypeHelper.createUniqueStructure(c, componentMap_3);

                c.updateRangeMorphingDataType(nestStartOffset, nestEndOffset, new HashSet<>(Set.of(structDT_1, structDT_3)));

                Logging.debug("Generator",
                        String.format("Found a match of complex flatten (%d) from offset 0x%x with %d count", capacity, offsets.get(i), flattenCnt));
                Logging.debug("Generator",
                        String.format("Window's DataType:\n%s", winDT));
            }
        }
    }

    /**
     * Get the component map of the Type Constraint, parameter `constraint` should not have conflicts
     * @param constraint the composite type constraint
     * @return the component map used for creating structure
     */
    private Map<Integer, DataType> getComponentMapByMostAccessed(TypeConstraint constraint) {
        var componentMap = new TreeMap<Integer, DataType>();
        for (var entry: constraint.innerSkeleton.fieldAccess.entrySet()) {
            var offset = entry.getKey();
            var aps = entry.getValue();
            var mostAccessedDT = aps.mostAccessedDT;

            if (constraint.finalPtrReference.containsKey(offset)) {
                createPtrRefMember(constraint, componentMap, offset);
                continue;
            }

            componentMap.put(offset.intValue(), mostAccessedDT);
        }
        return componentMap;
    }

    private Map<Integer, DataType> getComponentMapBySpecifyDT(TypeConstraint skt, long specOffset, DataType specDT) {
        var componentMap = new TreeMap<Integer, DataType>();
        for (var entry: skt.innerSkeleton.fieldAccess.entrySet()) {
            var offset = entry.getKey();
            var aps = entry.getValue();

            if (skt.finalPtrReference.containsKey(offset)) {
                createPtrRefMember(skt, componentMap, offset);
                continue;
            }

            if (offset != specOffset) {
                var mostAccessedDT = aps.mostAccessedDT;
                componentMap.put(offset.intValue(), mostAccessedDT);
            } else {
                componentMap.put(offset.intValue(), specDT);
            }
        }
        return componentMap;
    }

    /**
     * Create union at the specified offset, other fields using the most accessed data type
     * @param constraint the skeleton
     * @param offset the offset to create union
     * @return the component map
     */
    private Map<Integer, DataType> getComponentMapByUnionFields(TypeConstraint constraint, long offset) {
        var componentMap = new TreeMap<Integer, DataType>();
        for (var entry: constraint.innerSkeleton.fieldAccess.entrySet()) {
            var fieldOffset = entry.getKey().intValue();

            if (constraint.finalPtrReference.containsKey((long) fieldOffset)) {
                createPtrRefMember(constraint, componentMap, (long) fieldOffset);
                continue;
            }

            var aps = entry.getValue();
            if (fieldOffset == offset) {
                var unionDT = DataTypeHelper.createAnonUnion(constraint, offset);
                componentMap.put(fieldOffset, unionDT);
            } else {
                var mostAccessedDT = aps.mostAccessedDT;
                componentMap.put(fieldOffset, mostAccessedDT);
            }
        }
        return componentMap;
    }


    /**
     * Create a structure by combining flatten fields into array at the specified offset
     * @param skt the skeleton
     * @param flattenStartOffset the start offset of the flatten fields
     * @param winDT the flattened element data types
     * @param flattenCnt the count of the flatten fields
     * @return the component map
     */
    private Map<Integer, DataType> getComponentMapByRecoverFlattenToArray(TypeConstraint skt, long flattenStartOffset,
                                                                          DataType winDT, int flattenCnt) {
        var componentMap = new TreeMap<Integer, DataType>();
        long flattenEndOffset = flattenStartOffset + (long) winDT.getLength() * flattenCnt;

        for (var entry: skt.innerSkeleton.fieldAccess.entrySet()) {
            var fieldOffset = entry.getKey();
            if (fieldOffset < flattenStartOffset || fieldOffset >= flattenEndOffset) {
                DataType dt;
                if (skt.finalPtrReference.containsKey(fieldOffset)) {
                    createPtrRefMember(skt, componentMap, fieldOffset);
                } else {
                    dt = entry.getValue().mostAccessedDT;
                    componentMap.put(fieldOffset.intValue(), dt);
                }
            }
            /* Handle Flatten */
            else if (fieldOffset == flattenStartOffset) {
                var flattenDT = DataTypeHelper.createArray(winDT, flattenCnt);
                componentMap.put(fieldOffset.intValue(), flattenDT);
            }
        }

        return componentMap;
    }


    /**
     * Create a structure by combining flatten fields into series of nested structures at the specified offset
     * @param skt the skeleton
     * @param flattenStartOffset the start offset of the flatten fields
     * @param winDT the flattened element data types
     * @param flattenCnt the count of the flatten fields
     * @return the component map
     */
    private Map<Integer, DataType> getComponentMapByRecoverFlattenToNest(TypeConstraint skt, long flattenStartOffset,
                                                                         DataType winDT, int flattenCnt) {
        var componentMap = new TreeMap<Integer, DataType>();
        long flattenEndOffset = flattenStartOffset + (long) winDT.getLength() * flattenCnt;

        for (var entry: skt.innerSkeleton.fieldAccess.entrySet()) {
            var fieldOffset = entry.getKey();
            if (fieldOffset < flattenStartOffset || fieldOffset >= flattenEndOffset) {
                DataType dt;
                if (skt.finalPtrReference.containsKey(fieldOffset)) {
                    createPtrRefMember(skt, componentMap, fieldOffset);
                } else {
                    dt = entry.getValue().mostAccessedDT;
                    componentMap.put(fieldOffset.intValue(), dt);
                }
            }
            /* Handle Flatten */
            else if (fieldOffset == flattenStartOffset) {
                for (int i = 0; i < flattenCnt; i++) {
                    componentMap.put(fieldOffset.intValue() + i * winDT.getLength(), winDT);
                }
            }
        }

        return componentMap;
    }


    private void createPtrRefMember(TypeConstraint constraint, Map<Integer, DataType> componentMap, Long offset) {
        var ptrEE = constraint.finalPtrReference.get(offset);
        DataType dt;
        if (ptrEE.mayPointerToPrimitiveArray && ptrEE.finalType != null) {
            dt = DataTypeHelper.getPointerDT(ptrEE.finalType, constraint.ptrLevel.get(offset) != null ? constraint.ptrLevel.get(offset) : 1);
        } else {
            dt = DataTypeHelper.getPointerDT(DataTypeHelper.getDataTypeByName("void"),
                    constraint.ptrLevel.get(offset) != null ? constraint.ptrLevel.get(offset) : 1);
        }
        componentMap.put(offset.intValue(), dt);
        return;
    }

    public void explore() {
        for (var constraint: finalTypeConstraints) {
            if (constraint.mayPointerToPrimitiveArray) {
                Logging.debug("Generator", "May Pointer to Primitive Array Explored");
                constraint.dumpInfo();
            }
            else if (constraint.noMorphingTypes() && constraint.finalType != null) {
                Logging.debug("Generator", "No Morphing Stable Skeleton Explored");
                constraint.dumpInfo();
            }
            else {
                Logging.debug("Generator", "Morphing Skeleton Explored");
                constraint.dumpInfo();
            }
        }
    }
}
