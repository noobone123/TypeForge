package blueprint.solver;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.skeleton.Skeleton;
import blueprint.base.dataflow.skeleton.SkeletonCollector;
import blueprint.utils.DataTypeHelper;
import blueprint.utils.Global;
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

        skeletonCollector.handleDecompilerInferredTypes();
    }

    /**
     * Generate all possible structure declarations for each skeleton.
     */
    public void run() {
        /* In rare cases, */
        findingMayArrayBySlidingWindow();
    }

    // TODO: how to handle nested (multi nested ?)
    //  1. try to merge nested if no conflicts found, if there are multiNested, choose the one with the most field
    //  2. try to scanning using sliding window like independent skeleton, consider nested and reference
    // TODO: handle evil nodes and evil sources
    // TODO: sliding window scan struct and local variables
    // TODO: generate type declaration first, then try to retype and get pseudo-code
    // TODO: assessing the signed field and unsigned field
    private void findingMayArrayBySlidingWindow() {
        var exprToSkeletonMap = skeletonCollector.exprToSkeletonMap;
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            if (skt.isMultiLevelPtr()) {
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
            else {
                Logging.info("Generator", "Normal Skeleton: " + skt);
                skt.dumpInfo();
            }
        }
    }

    private void handleNoNestedSkeleton(Skeleton skt) {
        if (skt.hasPtrReference()) {
            Logging.info("Generator", "No Nested && Has Ptr Reference");
            handleInconsistencyField(skt);
            skt.dumpInfo();
        } else {
            Logging.info("Generator", "No Nested && No Ptr Reference");
            if (skt.mayPrimitiveArray()) {
                Logging.info("Generator", "May Primitive Array Found");
                skt.mayPrimitiveArray = true;
                var aps = skt.finalConstraint.fieldAccess.get(0L);
                var elementType = AccessPoints.getMostAccessedDT(aps);
                var ptrToArrayType = generatePointerToPrimitive(elementType);
                if (ptrToArrayType == null) {
                    Logging.error("Generator", "Failed to generate array type");
                    return;
                } else {
                    skt.updateDerivedTypes(ptrToArrayType);
                }

                var structDT = DataTypeHelper.createUniqueStructure(skt.getSize());
                var componentMap = getComponentMapByMostAccessed(skt);
                DataTypeHelper.populateStructure(structDT, componentMap, skt);
                skt.updateDerivedTypes(DataTypeHelper.getPointerOfStruct(structDT));
                skt.dumpInfo();
            }
            else {
                Logging.info("Generator", "No Primitive Array Found");
                handleInconsistencyField(skt);
                handlePrimitiveFlatten(skt);
                skt.dumpInfo();
            }
        }
    }

    private void handleInconsistencyField(Skeleton skt) {
        for (var entry: skt.finalConstraint.fieldAccess.entrySet()) {
            var offset = entry.getKey();
            var aps = entry.getValue();
            /* If Contains Ptr Reference, this field should be a ptrReference */
            if (!AccessPoints.ifAPSetHoldsSameSizeType(aps) &&
                    !skt.ptrReference.containsKey(offset)) {
                Logging.info("Generator", String.format("Inconsistency Field: Offset = 0x%s", Long.toHexString(offset)));

                // Create Union or Find the most accessed data type
                // TODO: remember to add getPointerOfStruct
                var structDT_1 = DataTypeHelper.createUniqueStructure(skt.getSize());
                var componentMap_1 = getComponentMapByMostAccessed(skt);
                DataTypeHelper.populateStructure(structDT_1, componentMap_1, skt);
                skt.morphingPoints.computeIfAbsent(offset, k -> new HashSet<>()).add(structDT_1);

                var structDT_2 = DataTypeHelper.createUniqueStructure(skt.getSize());
                var componentMap_2 = getComponentMapByUnionFields(skt, offset);
                DataTypeHelper.populateStructure(structDT_2, componentMap_2, skt);
                skt.morphingPoints.computeIfAbsent(offset, k -> new HashSet<>()).add(structDT_2);
            }
        }
    }

    // TODO: check if correct ...
    private void handlePrimitiveFlatten(Skeleton skt) {
        List<Long> offsets = new ArrayList<>(skt.finalConstraint.fieldAccess.keySet());
        for (int i = 0; i < offsets.size(); i++) {
            var offset = offsets.get(i);
            var aps = skt.finalConstraint.fieldAccess.get(offset);
            if (!skt.mustPrimitiveTypeAtOffset(offset)) {
                continue;
            }

            var temp = new TreeMap<Long, Integer>();
            temp.put(offset, AccessPoints.getDataTypeSize(aps));

            for (int j = i + 1; j < offsets.size(); j++) {
                var offset_j = offsets.get(j);
                var aps_j = skt.finalConstraint.fieldAccess.get(offset_j);
                if (!skt.mustPrimitiveTypeAtOffset(offset_j)) {
                    break;
                }

                // If current dataType's size equals last dataType's size in temp
                if (AccessPoints.getDataTypeSize(aps_j) == temp.get(offsets.get(j - 1))) {
                    temp.put(offset_j, AccessPoints.getDataTypeSize(aps_j));
                } else {
                    break;
                }
            }

            if (temp.size() > 3 && hasEqualInterval(temp.keySet())) {
                Logging.info("Generator", String.format("Flatten Primitive Found At 0x%s", Long.toHexString(offset)));
                skt.dumpInfo();

                // Skip over the window size to avoid redundant checks
                i += temp.size() - 1;
            }
        }
    }

    private void handlePointerToPrimitive(Skeleton skt) {
        Logging.info("Generator", "Field = 1 && Offset = 0");
        var aps = skt.finalConstraint.fieldAccess.get(0L);
        var mostAccessedDT = AccessPoints.getMostAccessedDT(aps);
        var pointerType = generatePointerToPrimitive(mostAccessedDT);
        if (pointerType == null) {
            Logging.error("Generator", "Failed to handle F = 1 && Offset = 0");
            return;
        } else {
            skt.setPrimitiveType(pointerType);
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
            var offset = entry.getKey().intValue();
            if (skt.ptrReference.containsKey((long) offset)) {
                var ptrLevel = skt.ptrLevel.get((long) offset);
                var dt = DataTypeHelper.getDataTypeByName("void");
                dt = DataTypeHelper.getPointerDT(dt, ptrLevel);
                componentMap.put(offset, dt);
                continue;
            }

            var aps = entry.getValue();
            var mostAccessedDT = AccessPoints.getMostAccessedDT(aps);
            componentMap.put(offset, mostAccessedDT);
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
            if (skt.ptrReference.containsKey((long) fieldOffset)) {
                var ptrLevel = skt.ptrLevel.get((long) fieldOffset);
                var dt = DataTypeHelper.getDataTypeByName("void");
                dt = DataTypeHelper.getPointerDT(dt, ptrLevel);
                componentMap.put(fieldOffset, dt);
                continue;
            }

            var aps = entry.getValue();
            if (fieldOffset == offset) {
                var unionDT = DataTypeHelper.createUniqueUnion(AccessPoints.getDataTypes(aps));
                componentMap.put(fieldOffset, unionDT);
            } else {
                var mostAccessedDT = AccessPoints.getMostAccessedDT(aps);
                componentMap.put(fieldOffset, mostAccessedDT);
            }
        }
        return componentMap;
    }

    private boolean hasEqualInterval(Set<Long> offsetArray) {
        if (offsetArray.size() < 2) {
            return true;
        }

        List<Long> offsetList = new ArrayList<>(offsetArray);
        Collections.sort(offsetList);

        long interval = offsetList.get(1) - offsetList.get(0);
        for (int i = 1; i < offsetList.size() - 1; i++) {
            if (offsetList.get(i + 1) - offsetList.get(i) != interval) {
                return false;
            }
        }
        return true;
    }


    public void explore() {
        var exprToSkeletonMap = skeletonCollector.exprToSkeletonMap;
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
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
