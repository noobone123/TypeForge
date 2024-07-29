package blueprint.solver;

import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.base.dataflow.SymbolExpr.SymbolExprManager;
import blueprint.base.dataflow.skeleton.SkeletonCollector;
import blueprint.base.dataflow.skeleton.TypeConstraint;
import blueprint.utils.Logging;

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

    public void explore() {
        var exprToSkeletonMap = skeletonCollector.exprToSkeletonMap;
        for (var skt: new HashSet<>(exprToSkeletonMap.values())) {
            if (skt.isMultiLevelPtr()) continue;
            Logging.info("Generator", " ------------------------------- Start --------------------------------- ");
            if (skt.hasMultiConstraints) {
                Logging.info("Generator", String.format("Exploring %s : C > 1, = %d", skt, skt.constraints.size()));
            } else {
                Logging.info("Generator", String.format("Exploring %s : C = 1", skt));
            }
            Logging.info("Generator", "Associated Exprs Count: " + skt.exprs.size());
            Logging.info("Generator", "All Exprs: " + skt.exprs);
            Logging.info("Generator", "Associated Variables Count: " + skt.getVariables().size());
            Logging.info("Generator", "All Variables: " + skt.getVariables());
            Logging.info("Generator", "Constraint:\n " + skt.finalConstraint);
            Logging.info("Generator", skt.finalConstraint.dumpLayout(0));
            Logging.info("Generator", "All Decompiler Inferred Types:\n" + skt.derivedTypes);

            Logging.info("Generator", " ------------------------------- End --------------------------------- ");
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


    public void buildSkeleton(SymbolExpr expr, TypeConstraint constraint) {
        constraint.accessOffsets.forEach((ap, offsets) -> {
            if (offsets.size() > 1) {
                for (var offset : offsets) {
                    // If one pcode Access Multiple fields, we should add a tag to the field
                    constraint.addFieldAttr(offset, TypeConstraint.Attribute.SAME_ACCESS_ON_MULTI_OFFSETS);
                }
            }
        });
    }
}
