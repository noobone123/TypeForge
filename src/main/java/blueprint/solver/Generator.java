package blueprint.solver;

import blueprint.base.dataflow.SymbolExpr.SymbolExpr;
import blueprint.base.dataflow.skeleton.TypeConstraint;
import blueprint.base.dataflow.context.InterContext;
import blueprint.utils.Logging;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighSymbol;

import java.io.File;
import java.io.IOException;
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
 * Finally, We take the pseudo code and Calculate the score for them, and find the best one as the final Structure Type
 */
public class Generator {
    // TODO: add decompiler inferred data type into polymorphic data type.
    public InterContext solverCtx;
    public final Map<Function, Map<HighSymbol, TypeConstraint>> funcConstraintMap = new HashMap<>();
    public final Map<HighSymbol, TypeConstraint> globalConstraintMap = new HashMap<>();

    public final Map<SymbolExpr, TypeConstraint> exprToConstraint;
    public final Map<HighSymbol, TypeConstraint> builtConstraints = new HashMap<>();


    public Generator(InterContext solverCtx) {
        this.solverCtx = solverCtx;
        this.exprToConstraint = new HashMap<>(solverCtx.symExprManager.getExprToConstraintMap());
        buildConstraintMap();

        for (var entry: exprToConstraint.entrySet()) {
            buildSkeleton(entry.getKey(), entry.getValue());
        }
    }

    public void buildConstraintMap() {
        for (var entry : exprToConstraint.entrySet()) {
            var expr = entry.getKey();
            if (expr.isVariable()) {
                var highSym = expr.getRootHighSymbol();
                if (highSym.isGlobal()) {
                    globalConstraintMap.put(highSym, entry.getValue());
                } else {
                    var func = highSym.getHighFunction().getFunction();
                    funcConstraintMap.computeIfAbsent(func, k -> new HashMap<>());
                    funcConstraintMap.get(func).put(highSym, entry.getValue());
                }
            }
        }
    }

//    public void buildSkeletonOfVariable() {
//        var funcNode = solverCtx.callGraph.getNodebyAddr(FunctionHelper.getAddress(0x001492c8));
//        var highSymbol = funcNode.getHighSymbolbyName("param_1");
//
//        var constraint = funcConstraintMap.get(funcNode.value).get(highSymbol);
//        if (constraint != null) {
//            Logging.info("Generator", String.format("Building Skeleton for Function %s -> %s",
//                                funcNode.value.getName(), highSymbol.getName()));
//            buildSkeleton();
//        } else {
//            Logging.error("Generator", String.format("No Constraint found for Function %s -> %s",
//                                funcNode.value.getName(), highSymbol.getName()));
//        }
//    }
//
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
