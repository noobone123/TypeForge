package blueprint.solver;

import blueprint.base.dataflow.AccessPoint;
import blueprint.base.dataflow.KSet;
import blueprint.base.dataflow.UnionFind;
import blueprint.base.dataflow.constraints.ComplexTypeConstraint;
import blueprint.base.dataflow.constraints.TypeDescriptor;
import blueprint.base.graph.CallGraph;
import blueprint.base.node.FunctionNode;
import blueprint.utils.Logging;
import blueprint.base.dataflow.SymbolExpr;

import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.*;

/**
 * The context used to store the relationship between HighSymbol and TypeBuilder.
 */
public class Context {

    public static class IntraContext {
        /** The candidate HighSymbols that need to collect data-flow facts */
        public final HashSet<HighSymbol> tracedSymbols;
        public final HashSet<Varnode> tracedVarnodes;

        public final HashSet<SymbolExpr> allSymbolExprs;

        /** Dataflow facts collected from the current function, each varnode may hold PointerRef from different base varnode and offset */
        public HashMap<Varnode, KSet<SymbolExpr>> dataFlowFacts;
        public int dataFlowFactKSize = 10;

        public IntraContext() {
            this.tracedSymbols = new HashSet<>();
            this.tracedVarnodes = new HashSet<>();
            this.allSymbolExprs = new HashSet<>();
            this.dataFlowFacts = new HashMap<>();
        }
    }

    public HashMap<FunctionNode, IntraContext> intraCtxMap;
    public HashMap<HighSymbol, ComplexTypeConstraint> symToConstraints;
    public UnionFind<SymbolExpr> symAliasMap;
    public CallGraph callGraph;

    public Context(CallGraph cg) {
        this.callGraph = cg;
        this.intraCtxMap = new HashMap<>();
        this.symToConstraints = new HashMap<>();
        this.symAliasMap = new UnionFind<>();
    }

    public void createIntraContext(FunctionNode funcNode) {
        IntraContext intraCtx = new IntraContext();
        intraCtxMap.put(funcNode, intraCtx);
    }

    public void addTracedSymbol(FunctionNode funcNode, HighSymbol highSymbol) {
        IntraContext intraCtx = intraCtxMap.get(funcNode);
        if (intraCtx == null) {
            Logging.error("Failed to get intraContext for " + funcNode.value.getName());
            return;
        }
        intraCtx.tracedSymbols.add(highSymbol);
    }

    public void addTracedVarnode(FunctionNode funcNode, Varnode vn) {
        var tracedVns = intraCtxMap.get(funcNode).tracedVarnodes;
        if (tracedVns.add(vn)) {
            Logging.debug("[DataFlow] Add traced varnode: " + vn);
        }
    }

    /**
     * create a new SymbolExpr and add it to the dataFlowFacts
     * @param funcNode the current function node
     * @param vn the varnode which holds the dataflow fact
     * @param symbolExpr the new symbolExpr
     */
    public void addNewSymbolExpr(FunctionNode funcNode, Varnode vn, SymbolExpr symbolExpr) {
        var intraCtx = intraCtxMap.get(funcNode);
        if (intraCtx == null) {
            Logging.error("Failed to get intraContext for " + funcNode.value.getName());
            return;
        }
        var curDataFlowFact = intraCtx.dataFlowFacts.computeIfAbsent(vn, k -> new KSet<>(intraCtx.dataFlowFactKSize));

        if (curDataFlowFact.add(symbolExpr)) {
            Logging.debug("[DataFlow] New " + vn + " -> " + curDataFlowFact);
        }
    }


    /**
     * Merge the dataflow facts from input to output
     * @param funcNode the current function node
     * @param input the input varnode
     * @param output the output varnode
     * @param isStrongUpdate if true, the output varnode's dataflow facts will be cleared before merging
     */
    public void mergeSymbolExpr(FunctionNode funcNode, Varnode input, Varnode output, boolean isStrongUpdate) {
        var intraCtx = intraCtxMap.get(funcNode);
        assert intraCtx != null;
        var dataFlowFacts = intraCtx.dataFlowFacts;
        var inputFacts = dataFlowFacts.get(input);

        if (inputFacts == null) {
            Logging.warn("Failed to get dataflow fact for " + input);
            return;
        }

        var outputFacts = dataFlowFacts.computeIfAbsent(output, k -> new KSet<>(intraCtx.dataFlowFactKSize));
        if (isStrongUpdate) {
            outputFacts.clear();
        }

        outputFacts.merge(inputFacts);
        Logging.debug("[DataFlow] Merge " + output + " -> " + outputFacts);
    }

    /**
     * Initialize the dataFlowFacts using the candidate HighSymbols
     */
    public void initIntraDataFlowFacts(FunctionNode funcNode) {
        var intraCtx = intraCtxMap.get(funcNode);
        // Update the interestedVn
        for (var symbol: intraCtx.tracedSymbols) {
            var highVar = symbol.getHighVariable();
            Logging.info("Candidate HighSymbol: " + symbol.getName());

            // If a HighSymbol (like a parameter) is not be used in the function, it can not hold a HighVariable
            if (highVar == null) {
                Logging.warn(funcNode.value.getName() + " -> HighSymbol: " + symbol.getName() + " has no HighVariable");
                continue;
            }

            // Initialize the dataFlowFacts using the interested varnodes and add
            // all varnode instances of the HighVariable to the IntraContext's tracedVarnodes
            // TODO: this may cause flow-insensitive, ... we can improve it in the future
            for (var vn: highVar.getInstances()) {
                addTracedVarnode(funcNode, vn);
                var symExpr = new SymbolExpr.Builder()
                                .rootSymbol(symbol)
                                .build();

                addNewSymbolExpr(funcNode, vn, symExpr);
            }
        }
    }

    public boolean isInterestedVn(FunctionNode funcNode, Varnode vn) {
        var intraCtx = intraCtxMap.get(funcNode);
        return intraCtx.tracedVarnodes.contains(vn);
    }

    public void createAccessPoint(FunctionNode funcNode, PcodeOp pcodeOp, SymbolExpr symExpr, TypeDescriptor type, boolean isLoad) {
        var accessPoint = new AccessPoint(pcodeOp, symExpr, type, isLoad);
        // symToConstraints.computeIfAbsent(symExpr.getBaseSymbol(), k -> new ComplexTypeConstraint()).addAccessPoint(accessPoint);
        if (isLoad) {
            Logging.info(String.format("[Load] Found load operation: %s -> %s", symExpr, type));
        } else {
            Logging.info(String.format("[Store] Found store operation: %s -> %s", symExpr, type));
        }
    }


    public KSet<SymbolExpr> getIntraDataFlowFacts(FunctionNode funcNode, Varnode vn) {
        var intraCtx = intraCtxMap.get(funcNode);
        var res = intraCtx.dataFlowFacts.get(vn);
        if (res == null) {
            Logging.warn("Failed to get dataflow fact for " + vn);
            return null;
        }
        return res;
    }

    public void updateSymbolAliasMap(SymbolExpr sym1, SymbolExpr sym2) {
        symAliasMap.union(sym1, sym2);
        Logging.debug(String.format("[Alias] %s -> %s", sym1, sym2));
    }

    /**
     * Build the complex data type's constraints for the HighSymbol based on the AccessPoints calculated from intraSolver.
     * All HighSymbol with ComplexType should in the tracedSymbols set.
     */
    // TODO: this method should be called after all functions are solved, now it is called after each function is solved for debugging
//    public void buildComplexTypeConstraints() {
//        // Step1: merge constraint's access points using the alias map
//        symAliasMap.getComponents().values().forEach(component -> {
//            Logging.debug("[Alias] Merging component: " + component);
//            ComplexTypeConstraint newConstraint = new ComplexTypeConstraint();
//
//            // TODO: handle cases when symExpr's offset is not 0
//            for (var symExpr: component) {
//                var highSym = symExpr.getBaseSymbol();
//                var otherConstraint = symToConstraints.get(highSym);
//                if (otherConstraint != null) {
//                    newConstraint.mergeAccessPoints(otherConstraint);
//                }
//            }
//
//            for (var symExpr: component) {
//                symToConstraints.put(symExpr.getBaseSymbol(), newConstraint);
//                Logging.debug("[Alias] " + symExpr + " -> " + newConstraint.getName());
//            }
//        });
//
//
//        // Step2: build the fieldMap using the merged access points
//        var constraintsSet = new HashSet<>(symToConstraints.values());
//        for (var constraint: constraintsSet) {
//            constraint.buildConstraint();
//        }
//    }


    public boolean isFunctionSolved(FunctionNode funcNode) {
        return intraCtxMap.containsKey(funcNode);
    }


    public void dumpIntraComplexType(FunctionNode funcNode) {
        var intraCtx = intraCtxMap.get(funcNode);
        for (var highSym: intraCtx.tracedSymbols) {
            var complexType = symToConstraints.get(highSym);
            if (complexType != null) {
                Logging.info("[TypeConstraints] " + highSym.getName() + " -> " + complexType);
            }
        }
    }

//    /**
//     * Merge the TypeBuilder of the other intraSolver's context to the current context.
//     * @param other the callee intraSolver's context
//     * @param from the HighSymbol in the other context
//     * @param to the HighSymbol in the current context
//     * @param offset the offset of `to` highSymbol's field
//     * @return true if the merge is successful
//     */
//    public boolean updateTypeBuilderFromCallee(Context other, HighSymbol from, HighSymbol to, long offset) {
//        if (!other.typeBuilderMap.containsKey(from)) {
//            Logging.error("No HighSymbol in the other context");
//            return false;
//        }
//
//        var otherTypeBuilder = other.typeBuilderMap.get(from);
//        if (offset == 0) {
//            typeBuilderMap.put(to, otherTypeBuilder);
//            otherTypeBuilder.addTag(0, "ARGUMENT");
//        } else {
//            var typeBuilder = typeBuilderMap.computeIfAbsent(to, k -> new TypeCollector());
//            typeBuilder.addTypeBuilder(offset, otherTypeBuilder);
//            typeBuilder.addTag(offset, "ARGUMENT");
//        }
//
//        return true;
//    }
}
