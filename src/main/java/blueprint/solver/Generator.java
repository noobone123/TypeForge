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

        skeletonCollector.handleAPSets();
        skeletonCollector.handleDecompilerInferredTypes();
    }

    /**
     * Generate all possible structure declarations for each skeleton.
     */
    public void run() {
        /* In rare cases, */
        ttt();
    }

    private void ttt() {
        var exprToSkeletonMap = skeletonCollector.exprToSkeletonMap;
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            if (skt.isMultiLevelPtr()) {
                // TODO: handle multi-level ptr， if there skt's exprs has variable.
                Logging.info("Generator", "Multi Level Ptr Skeleton: " + skt);
                continue;
            }
            else if (skt.isIndependent() && skt.hasOneField() &&
                    !skt.decompilerInferredTypesHasComposite() &&
                    (skt.finalConstraint.fieldAccess.get(0L) != null)) {
                /* These types are considered as pointers to primitive types and no need to assess and ranking */
                handlePointerToPrimitive(skt);
            }
            else if (!skt.hasNestedSkeleton()) {
                /* If No Nested Skeleton Found */
                Logging.info("Generator", "No Nested Skeleton: " + skt);
                handleNoNestedSkeleton(skt);
            }
            else if (skt.hasNestedSkeleton()) {
                handleNestedSkeleton(skt);
            }
        }
    }

    // TODO: Handle Nested Skeleton finally
    //  1. If nest or not ?
    //  2. If nested, we just mark relationship and copy all member from nestee to nester, without create nested structure, because nested structure may has ????
    //  3. If nested, we utilize size and sliding window to find the flatten.
    //  4. For other fields that not contained in the nested intervals, we should handle them by `handleInconsistencyField` and `handlePrimitiveFlatten` and `handleComplexFlatten`
    private void handleNestedSkeleton(Skeleton skt) {
        for (var offset: skt.mayNestedSkeleton.keySet()) {
            var nestedSktSet = skt.mayNestedSkeleton.get(offset);
            if (nestedSktSet.size() == 1) {
                var nestedSkt = nestedSktSet.iterator().next();

                Logging.info("Generator", String.format("Nested Skeleton Found At 0x%s", Long.toHexString(offset)));
                skt.dumpInfo();
                nestedSkt.dumpInfo();
            }
        }
    }

    private void handleNoNestedSkeleton(Skeleton skt) {
        if (skt.hasPtrReference()) {
            Logging.info("Generator", "No Nested && Has Ptr Reference");
            handleInconsistencyField(skt);
            handlePrimitiveFlatten(skt);
            // TODO: handle complex flatten
            // TODO: Using a larger sliding window size and considering the ptrReference Information
            // TODO: When using a large sliding window, if elements in current window's size is equal, we do not build this window.
        } else {
            Logging.info("Generator", "No Nested && No Ptr Reference");
            if (skt.mayPrimitiveArray()) {
                Logging.info("Generator", "May Primitive Array Found");
                handleMayPrimitiveArray(skt);
            }
            else {
                Logging.info("Generator", "No Primitive Array Found");
                handleInconsistencyField(skt);
                handlePrimitiveFlatten(skt);
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
        Logging.info("Generator",componentMap.toString());
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

    private void handlePointerToPrimitive(Skeleton skt) {
        Logging.info("Generator", "Field = 1 && Offset = 0");
        var aps = skt.finalConstraint.fieldAccess.get(0L);
        var mostAccessedDT = aps.mostAccessedDT;
        var pointerType = generatePointerToPrimitive(mostAccessedDT);
        if (pointerType == null) {
            Logging.error("Generator", "Failed to handle F = 1 && Offset = 0");
        } else {
            skt.setPrimitiveType(pointerType);
        }
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
                var componentMap_1 = getComponentMapByMostAccessed(skt);
                var structDT_1 = DataTypeHelper.createUniqueStructure(skt, componentMap_1);

                var componentMap_2 = getComponentMapByUnionFields(skt, offset);
                var structDT_2 = DataTypeHelper.createUniqueStructure(skt, componentMap_2);

                skt.updateRangeMorphingDataType(offset, offset, Set.of(structDT_1, structDT_2));
            }
        }
    }

    private void handlePrimitiveFlatten(Skeleton skt) {
        List<Long> offsets = new ArrayList<>(skt.finalConstraint.fieldAccess.keySet());
        SlidingWindowProcessor windowProcessor = new SlidingWindowProcessor(skt, offsets, 1);

        for (int i = 0; i < offsets.size() - 1; i++) {
            var curOffset = offsets.get(i);
            var hasFlattenWindow = windowProcessor.tryMatchingFromCurrentOffset(i);
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
            skt.updateRangeMorphingDataType(startOffset, endOffset, Set.of(structDT_1, structDT_2));

            Logging.info("Generator",
                    String.format("Found a match from offset 0x%x with %d elements", curOffset, flattenCnt));
            Logging.info("Generator",
                    String.format("Window's DataType:\n%s", winDT));
            skt.dumpInfo();

            windowProcessor.resetFlattenCnt();
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
                var dt = DataTypeHelper.getPointerDT(DataTypeHelper.getDataTypeByName("void"),
                        skt.ptrLevel.get(offset));
                componentMap.put(offset.intValue(), dt);
                continue;
            }

            componentMap.put(offset.intValue(), mostAccessedDT);
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
                var dt = DataTypeHelper.getPointerDT(DataTypeHelper.getDataTypeByName("void"),
                        skt.ptrLevel.get((long) fieldOffset));
                componentMap.put(fieldOffset, dt);
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
                    dt = DataTypeHelper.getPointerDT(DataTypeHelper.getDataTypeByName("void"),
                            skt.ptrLevel.get(fieldOffset));
                } else {
                    dt = entry.getValue().mostAccessedDT;
                }
                componentMap.put(fieldOffset.intValue(), dt);
            }

            /* Handle Flatten */
            else if (fieldOffset == flattenStartOffset) {
                var flattenDT = DataTypeHelper.createArray(winDT, flattenCnt);
                componentMap.put(fieldOffset.intValue(), flattenDT);
            }
        }

        return componentMap;
    }

    public void explore() {
        var exprToSkeletonMap = skeletonCollector.exprToSkeletonMap;
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            Logging.info("Generator", String.format("Exploring Skeleton: %s", skt));
            if (skt.isMultiLevelPtr()) continue;
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
