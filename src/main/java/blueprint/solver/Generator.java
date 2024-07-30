package blueprint.solver;

import blueprint.base.dataflow.AccessPoints;
import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.skeleton.Skeleton;
import blueprint.base.dataflow.skeleton.SkeletonCollector;
import blueprint.base.dataflow.skeleton.TypeConstraint;
import blueprint.utils.DataTypeHelper;
import blueprint.utils.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;

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

    // TODO: derived types should not has overlap conflict with skeleton's final Constraint
    // TODO: how to handle nested (multi nested ?)
    //  1. try to merge nested if no conflicts found, if there are multiNested, choose the one with the most field
    //  2. try to scanning using sliding window like independent skeleton, consider nested and reference
    // TODO: handle evil nodes and evil sources
    // TODO: handle stack variables
    // TODO: generate type declaration first, then try to retype and get pseudo-code
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

                var length = skt.getSize();
                Logging.info("Generator", "Generating Structure Type with Length: " + length);
                var structDT = DataTypeHelper.createUniqueStructure(length);
                var componentMap = skt.getComponentMap();
                populateStructure(structDT, componentMap);
                skt.updateDerivedTypes(structDT);

                skt.dumpInfo();
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

    private void populateStructure(Structure structDT, Map<Long, DataType> componentMap) {
        // TODO: ...
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
