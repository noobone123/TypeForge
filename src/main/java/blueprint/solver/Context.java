package blueprint.solver;

import blueprint.base.dataflow.KSet;
import blueprint.base.dataflow.UnionFind;
import blueprint.base.dataflow.type.ComplexType;
import blueprint.base.dataflow.type.GeneralType;
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

    public static class AccessPoint {
        public final PcodeOp pcodeOp;
        public final SymbolExpr symExpr;
        public final GeneralType type;
        public final boolean isLoad;

        public AccessPoint(PcodeOp pcodeOp, SymbolExpr symExpr, GeneralType type, boolean isLoad) {
            this.pcodeOp = pcodeOp;
            this.symExpr = symExpr;
            this.type = type;
            this.isLoad = isLoad;
        }

        @Override
        public String toString() {
            return String.format("%s -> %s", symExpr, type);
        }
    }

    public static class IntraContext {
        /** The candidate HighSymbols that need to collect data-flow facts */
        public final HashSet<HighSymbol> tracedSymbols;
        public final HashSet<Varnode> tracedVarnodes;

        public final HashSet<SymbolExpr> allSymbolExprs;

        /** Dataflow facts collected from the current function, each varnode may hold PointerRef from different base varnode and offset */
        public HashMap<Varnode, KSet<SymbolExpr>> dataFlowFacts;
        public int dataFlowFactKSize = 10;

        /** This map is used to record the DataType's load/store operation on traced varnodes */
        public HashMap<HighSymbol, Set<AccessPoint>> symbolToAccessPoints;

        public IntraContext() {
            this.tracedSymbols = new HashSet<>();
            this.tracedVarnodes = new HashSet<>();
            this.allSymbolExprs = new HashSet<>();
            this.dataFlowFacts = new HashMap<>();
            this.symbolToAccessPoints = new HashMap<>();
        }
    }

    public HashMap<FunctionNode, IntraContext> intraCtxMap;
    public HashMap<HighSymbol, ComplexType> globalSymToComplexType;
    public UnionFind<SymbolExpr> globalSymAliasMap;
    public HashMap<HighSymbol, Set<AccessPoint>> globalSymToAccessPoints;
    public CallGraph callGraph;

    public Context(CallGraph cg) {
        this.callGraph = cg;
        this.intraCtxMap = new HashMap<>();
        this.globalSymToComplexType = new HashMap<>();
        this.globalSymAliasMap = new UnionFind<>();
        this.globalSymToAccessPoints = new HashMap<>();
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
     * @param highSym the base HighSymbol of the dataflow fact
     * @param offset the offset of the SymbolExpr
     */
    public void addNewSymbolExpr(FunctionNode funcNode, Varnode vn, HighSymbol highSym, long offset) {
        var intraCtx = intraCtxMap.get(funcNode);
        if (intraCtx == null) {
            Logging.error("Failed to get intraContext for " + funcNode.value.getName());
            return;
        }
        var symbolExpr = new SymbolExpr(highSym, offset);
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
                addNewSymbolExpr(funcNode, vn, symbol, 0);
            }
        }
    }


    public boolean isInterestedVn(FunctionNode funcNode, Varnode vn) {
        var intraCtx = intraCtxMap.get(funcNode);
        return intraCtx.tracedVarnodes.contains(vn);
    }


    public void updateLoadStoreMap(FunctionNode funcNode, PcodeOp pcodeOp, SymbolExpr symExpr, GeneralType type, boolean isLoad) {
        var intraCtx = intraCtxMap.get(funcNode);
        var accessPoint = new AccessPoint(pcodeOp, symExpr, type, isLoad);
        intraCtx.symbolToAccessPoints.computeIfAbsent(symExpr.baseSymbol, k -> new HashSet<>()).add(accessPoint);
        globalSymToAccessPoints.computeIfAbsent(symExpr.baseSymbol, k -> new HashSet<>()).add(accessPoint);
        if (isLoad) {
            Logging.debug(String.format("[Load] Found load operation: %s -> %s", symExpr, type));
        } else {
            Logging.debug(String.format("[Store] Found store operation: %s -> %s", symExpr, type));
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


    public void updateSymbolAliasMap(HighSymbol sym1, long off1, HighSymbol sym2, long off2) {
        var se1 = new SymbolExpr(sym1, off1);
        var se2 = new SymbolExpr(sym2, off2);
        globalSymAliasMap.union(se1, se2);
        Logging.debug(String.format("[Alias] %s -> %s", se1, se2));
    }

    public void updateSymbolAliasMap(SymbolExpr sym1, SymbolExpr sym2) {
        globalSymAliasMap.union(sym1, sym2);
        Logging.debug(String.format("[Alias] %s -> %s", sym1, sym2));
    }

    /**
     * Build the complex data type for the HighSymbol based on the load/store maps calculated from intraSolver.
     * All HighSymbol with ComplexType should in the tracedSymbols set.
     * // TODO: buildComplexType may can also be called when all functions are solved, which can save time, currently we call it in the end of each function to debug
     */
    public void buildComplexType(FunctionNode funcNode) {
        var intraCtx = intraCtxMap.get(funcNode);

        // Step 1: Create initial ComplexTypes for all involved HighSymbols in current IntraContext
        Map<HighSymbol, ComplexType> initalComplexTypes = new HashMap<>();
        intraCtx.symbolToAccessPoints.forEach((highSym, accessPoints) -> {
            if (intraCtx.tracedSymbols.contains(highSym)) {
                var complexType = initalComplexTypes.computeIfAbsent(highSym, k -> new ComplexType());
                for (AccessPoint access : accessPoints) {
                    complexType.addField(access.symExpr.offset, access.type);
                }
            }
        });

        // Step 2: Merge ComplexTypes based on aliasing and distinct PCodeOps, merging is Inter-procedural
        Map<HighSymbol, ComplexType> mergedComplexTypes = new HashMap<>(initalComplexTypes);
        globalSymAliasMap.getComponents().values().forEach(component -> {
            Logging.debug("[Alias] Merging component: " + component);
            ComplexType mergedType = new ComplexType();
            Set<PcodeOp> usedPcodeOps = new HashSet<>();

            for (SymbolExpr symExpr : component) {
                HighSymbol highSym = symExpr.baseSymbol;
                var aps = globalSymToAccessPoints.get(highSym);
                if (aps == null) {
                    Logging.warn("No access points for " + highSym.getName());
                    continue;
                }
                for (var ap : aps) {
                    if (usedPcodeOps.add(ap.pcodeOp)) {
                        mergedType.addField(ap.symExpr.offset, ap.type);
                    }
                }
            }

            // Assign the merged type to all symbols in the component
            for (SymbolExpr symExpr : component) {
                mergedComplexTypes.put(symExpr.baseSymbol, mergedType);
                Logging.debug("[Alias] " + symExpr + " -> " + mergedType.getTypeName());
            }
        });

        // Step 3: Update references to point to the merged ComplexTypes
        globalSymToComplexType.putAll(mergedComplexTypes);
    }


    public boolean isFunctionSolved(FunctionNode funcNode) {
        return intraCtxMap.containsKey(funcNode);
    }


    public void dumpIntraComplexType(FunctionNode funcNode) {
        var intraCtx = intraCtxMap.get(funcNode);
        for (var highSym: intraCtx.tracedSymbols) {
            var complexType = globalSymToComplexType.get(highSym);
            if (complexType != null) {
                Logging.info("[ComplexType] " + highSym.getName() + " -> " + complexType);
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
