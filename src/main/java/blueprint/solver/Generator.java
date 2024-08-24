package blueprint.solver;

import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.skeleton.Skeleton;
import blueprint.base.dataflow.skeleton.SkeletonCollector;
import blueprint.base.passes.SlidingWindowProcessor;
import blueprint.utils.DataTypeHelper;
import blueprint.utils.Logging;
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
 * DataType Importer will create retype HighSymbols for each Structure Builder and get each Function's updated pseudo code.
 * Retype process should be done from callee to caller, which can utilize.
 * result: {
 *     "StructureBuilder_1": [pseudo_code_1, pseudo_code_2, ...],
 *     "StructureBuilder_2": [pseudo_code_3, pseudo_code_4, ...],
 *     ...
 * }
 * Finally, We take the pseudocode and Calculate the score for them, and find the best one as the final Structure Type
 */
public class Generator {
    public SkeletonCollector skeletonCollector;
    public SymbolExprManager exprManager;


    public Generator(SkeletonCollector skeletonCollector, SymbolExprManager exprManager) {
        this.skeletonCollector = skeletonCollector;
        this.exprManager = exprManager;
    }

    /**
     * Generate all possible structure declarations for each skeleton.
     */
    public void run() {
        /* In rare cases, */
        generation();
        // TODO: IMPORTANT - post handle struct declarations in the skt's morphing types.
        //  Because some different structure Object may have the fully same layout (including member's type name)
    }

    private void generation() {
        var exprToSkeletonMap = skeletonCollector.exprToSkeletonMap;
        // TODO: If there is ptrReference or Nested Skeleton related to Pointer to Primitive

        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            if (skt.isPointerToPrimitive) {
                Logging.info("Generator", "Pointer to Primitive Found");
                continue;
            }
            if (skt.isMultiLevelMidPtr) {
                Logging.info("Generator", "Multi-Level Mid Pointer Found");
                continue;
            }

            if (!skt.hasNestedSkeleton()) {
                /* If No Nested Skeleton Found */
                Logging.info("Generator", "No Nested Skeleton: " + skt);
                handleNoNestedSkeleton(skt);
            }
            else {
                Logging.info("Generator", "Has Nested Skeleton: " + skt);
                handleNestedSkeleton(skt);
            }
            // TODO: populate empty (not padding) intervals with char[]
        }
    }

    private void handleNestedSkeleton(Skeleton skt) {
        skt.dumpInfo();
        for (var offset: skt.mayNestedSkeleton.keySet()) {
            var nestedSktSet = skt.mayNestedSkeleton.get(offset);
            Logging.info("Generator", String.format("Nested Skeletons Found At 0x%s", Long.toHexString(offset)));
            for (var nestedSkt: nestedSktSet) {
                nestedSkt.dumpInfo();
            }
        }
    }

    private void handleNoNestedSkeleton(Skeleton skt) {
        if (skt.hasPtrReference()) {
            Logging.info("Generator", "No Nested && Has Ptr Reference");
            handleInconsistencyField(skt);
            handleComplexFlatten(skt);
            handlePrimitiveFlatten(skt);
        } else {
            Logging.info("Generator", "No Nested && No Ptr Reference");
            if (!skt.mayPrimitiveArray()) {
                Logging.info("Generator", "No Primitive Array Found");
                handleInconsistencyField(skt);
                handleComplexFlatten(skt);
                handlePrimitiveFlatten(skt);
            }
            else {
                Logging.info("Generator", "May Primitive Array Found");
                handleMayPrimitiveArray(skt);
            }
        }

        /* These Stable Types have no nested skeletons and no Incosistency and Primitive Flatten */
        if (skt.noMorphingTypes() && skt.finalType == null) {
            Logging.info("Generator", "Normal Skeleton");
            handleNormalSkeleton(skt);
        }
    }

    private void handleNormalSkeleton(Skeleton skt) {
        var componentMap = getComponentMapByMostAccessed(skt);
        var structDT = DataTypeHelper.createUniqueStructure(skt, componentMap);
        skt.setFinalType(structDT);
    }

    private void handleMayPrimitiveArray(Skeleton skt) {
        skt.mayPrimitiveArray = true;
        var aps = skt.finalConstraint.fieldAccess.get(0L);
        var elementType = aps.mostAccessedDT;
        var ptrToArrayType = generatePointerToPrimitive(elementType);
        if (ptrToArrayType == null) {
            Logging.error("Generator", "Failed to generate array type");
            return;
        }

        var componentMap = getComponentMapByMostAccessed(skt);
        var structDT = DataTypeHelper.createUniqueStructure(skt, componentMap);
        skt.updateGlobalMorphingDataType(ptrToArrayType);
        skt.updateGlobalMorphingDataType(DataTypeHelper.getPointerOfStruct(structDT));
    }

    private void handleInconsistencyField(Skeleton skt) {
        for (var entry: skt.finalConstraint.fieldAccess.entrySet()) {
            var offset = entry.getKey();
            var aps = entry.getValue();
            /* If Contains Ptr Reference, this field should be a ptrReference */
            if (!aps.isSameSizeType && !skt.finalPtrReference.containsKey(offset)) {
                Logging.info("Generator", String.format("Inconsistency Field: Offset = 0x%s", Long.toHexString(offset)));
                skt.markInconsistentOffset(offset);

                // Create Union or Find the most accessed data type
                var componentMap_u = getComponentMapByUnionFields(skt, offset);
                var structDT_u = DataTypeHelper.createUniqueStructure(skt, componentMap_u);
                var DTs = new HashSet<DataType>(Set.of(structDT_u));

                for (var dt: aps.allDTs) {
                    var componentMap = getComponentMapBySpecifyDT(skt, offset, dt);
                    var structDT = DataTypeHelper.createUniqueStructure(skt, componentMap);
                    DTs.add(structDT);
                }

                skt.updateRangeMorphingDataType(offset, offset + aps.maxDTSize, DTs);
            }
        }
    }

    private void handlePrimitiveFlatten(Skeleton skt) {
        List<Long> offsets = new ArrayList<>(skt.finalConstraint.fieldAccess.keySet());
        SlidingWindowProcessor windowProcessor = new SlidingWindowProcessor(skt, offsets, 1);

        for (int i = 0; i < offsets.size() - 1; i++) {
            var curOffset = offsets.get(i);
            var hasFlattenWindow = windowProcessor.tryMatchingFromCurrentOffset(i, 4);
            if (hasFlattenWindow.isEmpty()) { continue; }

            var window = hasFlattenWindow.get();
            DataType winDT = window.getWindowDT();
            int flattenCnt = windowProcessor.getFlattenCount();

            var componentMap_1 = getComponentMapByMostAccessed(skt);
            var structDT_1 = DataTypeHelper.createUniqueStructure(skt, componentMap_1);

            var componentMap_2 = getComponentMapByRecoverFlatten(skt, curOffset, winDT, flattenCnt);
            var structDT_2 = DataTypeHelper.createUniqueStructure(skt, componentMap_2);

            var startOffset = offsets.get(i).intValue();
            var endOffset = startOffset + window.getAlignedWindowSize() * flattenCnt;
            skt.updateRangeMorphingDataType(startOffset, endOffset, new HashSet<>(Set.of(structDT_1, structDT_2)));

            Logging.info("Generator",
                    String.format("Found a match of primitive flatten from offset 0x%x with %d count", curOffset, flattenCnt));
            Logging.info("Generator",
                    String.format("Window's DataType:\n%s", winDT));
            skt.dumpInfo();

            windowProcessor.resetFlattenCnt();
        }
    }

    private void handleComplexFlatten(Skeleton skt) {
        List<Long> offsets = new ArrayList<>(skt.finalConstraint.fieldAccess.keySet());
        SlidingWindowProcessor windowProcessor = new SlidingWindowProcessor(skt, offsets, 2);

        for (int i = 0; i < offsets.size() - 1; i++) {
            for (int capacity = 2; ((offsets.size() - i) / capacity) >= 2; capacity ++) {
                windowProcessor.setWindowCapacity(capacity);
                var hasFlattenWindow = windowProcessor.tryMatchingFromCurrentOffset(i, 2);
                if (hasFlattenWindow.isEmpty()) { continue; }

                var window = hasFlattenWindow.get();
                DataType winDT = window.getWindowDT();
                int flattenCnt = windowProcessor.getFlattenCount();

                var componentMap_1 = getComponentMapByMostAccessed(skt);
                var structDT_1 = DataTypeHelper.createUniqueStructure(skt, componentMap_1);
                var componentMap_2 = getComponentMapByRecoverFlatten(skt, offsets.get(i), winDT, flattenCnt);
                var structDT_2 = DataTypeHelper.createUniqueStructure(skt, componentMap_2);

                var startOffset = offsets.get(i).intValue();
                var endOffset = startOffset + window.getAlignedWindowSize() * flattenCnt;
                skt.updateRangeMorphingDataType(startOffset, endOffset, new HashSet<>(Set.of(structDT_1, structDT_2)));

                Logging.info("Generator",
                        String.format("Found a match of complex flatten (%d) from offset 0x%x with %d count", capacity, offsets.get(i), flattenCnt));
                Logging.info("Generator",
                        String.format("Window's DataType:\n%s", winDT));
                skt.dumpInfo();
            }
        }
    }

    private DataType generatePointerToPrimitive(DataType primitiveType) {
        var pointerType = DataTypeHelper.getPointerDT(primitiveType, 1);
        if (pointerType == null) {
            Logging.error("Generator", "Failed to generate pointer to primitive type");
            return null;
        } else {
            return pointerType;
        }
    }

    /**
     * Get the component map of the skeleton, parameter `skt` should not have conflicts
     * @param skt the skeleton
     * @return the component map
     */
    private Map<Integer, DataType> getComponentMapByMostAccessed(Skeleton skt) {
        var componentMap = new TreeMap<Integer, DataType>();
        for (var entry: skt.finalConstraint.fieldAccess.entrySet()) {
            var offset = entry.getKey();
            var aps = entry.getValue();
            var mostAccessedDT = aps.mostAccessedDT;

            if (skt.finalPtrReference.containsKey(offset)) {
                createPtrRefMember(skt, componentMap, offset);
                continue;
            }

            componentMap.put(offset.intValue(), mostAccessedDT);
        }
        return componentMap;
    }

    private Map<Integer, DataType> getComponentMapBySpecifyDT(Skeleton skt, long specOffset, DataType specDT) {
        var componentMap = new TreeMap<Integer, DataType>();
        for (var entry: skt.finalConstraint.fieldAccess.entrySet()) {
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
     * @param skt the skeleton
     * @param offset the offset to create union
     * @return the component map
     */
    private Map<Integer, DataType> getComponentMapByUnionFields(Skeleton skt, long offset) {
        var componentMap = new TreeMap<Integer, DataType>();
        for (var entry: skt.finalConstraint.fieldAccess.entrySet()) {
            var fieldOffset = entry.getKey().intValue();

            if (skt.finalPtrReference.containsKey((long) fieldOffset)) {
                createPtrRefMember(skt, componentMap, (long) fieldOffset);
                continue;
            }

            var aps = entry.getValue();
            if (fieldOffset == offset) {
                var unionDT = DataTypeHelper.createUniqueUnion(skt, offset);
                componentMap.put(fieldOffset, unionDT);
            } else {
                var mostAccessedDT = aps.mostAccessedDT;
                componentMap.put(fieldOffset, mostAccessedDT);
            }
        }
        return componentMap;
    }


    /**
     * Create a structure by combining flatten fields at the specified offset
     * @param skt the skeleton
     * @param flattenStartOffset the start offset of the flatten fields
     * @param winDT the flattened element data types
     * @param flattenCnt the count of the flatten fields
     * @return the component map
     */
    private Map<Integer, DataType> getComponentMapByRecoverFlatten(Skeleton skt, long flattenStartOffset,
                                                                   DataType winDT, int flattenCnt) {
        var componentMap = new TreeMap<Integer, DataType>();
        long flattenEndOffset = flattenStartOffset + (long) winDT.getLength() * flattenCnt;

        for (var entry: skt.finalConstraint.fieldAccess.entrySet()) {
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

    private void createPtrRefMember(Skeleton skt, Map<Integer, DataType> componentMap, Long offset) {
        var ptrEE = skt.finalPtrReference.get(offset);
        DataType dt;
        if (ptrEE.isPointerToPrimitive) {
            dt = DataTypeHelper.getPointerDT(ptrEE.finalType, skt.ptrLevel.get(offset));
        } else {
            dt = DataTypeHelper.getPointerDT(DataTypeHelper.getDataTypeByName("void"),
                    skt.ptrLevel.get(offset));
        }
        componentMap.put(offset.intValue(), dt);
        return;
    }

    public void explore() {
        // TODO: update explore function
        var exprToSkeletonMap = skeletonCollector.exprToSkeletonMap;
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            Logging.info("Generator", String.format("Exploring Skeleton: %s", skt));
            if (skt.isMultiLevelMidPtr()) continue;
            skt.dumpInfo();
        }

        Logging.info("Generator", String.format("Evil Sources (%d):", skeletonCollector.evilSource.size()));
        for (var source: skeletonCollector.evilSource) {
            Logging.info("Generator", source.toString());
        }
        Logging.info("Generator", String.format("Evil Nodes (%d):", skeletonCollector.evilNodes.size()));
        for (var node: skeletonCollector.evilNodes) {
            Logging.info("Generator", node.toString());
        }
        Logging.info("Generator", String.format("Evil Paths (%d):", skeletonCollector.evilPaths.size()));
        for (var path: skeletonCollector.evilPaths) {
            Logging.info("Generator", path.toString());
        }
    }
}
