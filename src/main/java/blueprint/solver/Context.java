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
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

import java.util.*;
import java.util.function.Consumer;

/**
 * The context used to store the relationship between HighSymbol and TypeBuilder.
 */
public class Context {

    public static class AccessPoint {
        public final PcodeOp pcodeOp;
        public final SymbolExpr symExpr;
        public final GeneralType type;

        public AccessPoint(PcodeOp pcodeOp, SymbolExpr symExpr, GeneralType type) {
            this.pcodeOp = pcodeOp;
            this.symExpr = symExpr;
            this.type = type;
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

        /** These 2 maps are used to record the DataType's load/store operation on traced varnodes */
        public HashSet<AccessPoint> allLoads;
        public HashSet<AccessPoint> allStores;

        public IntraContext() {
            this.tracedSymbols = new HashSet<>();
            this.tracedVarnodes = new HashSet<>();
            this.allSymbolExprs = new HashSet<>();
            this.dataFlowFacts = new HashMap<>();
            this.allLoads = new HashSet<>();
            this.allStores = new HashSet<>();
        }
    }

    public HashMap<FunctionNode, IntraContext> intraCtxMap;
    public HashMap<HighSymbol, ComplexType> symbol2ComplexType;
    public UnionFind<SymbolExpr> symbolAliasMap;
    public CallGraph callGraph;

    public Context(CallGraph cg) {
        this.callGraph = cg;
        this.intraCtxMap = new HashMap<>();
        this.symbol2ComplexType = new HashMap<>();
        this.symbolAliasMap = new UnionFind<>();
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
            for (var vn: highVar.getInstances()) {
                addTracedVarnode(funcNode, vn);
                addNewSymbolExpr(funcNode, vn, symbol, 0);
            }
        }
    }

    /**
     * If current PCodeOp's input varnode in tracedVarnodes, then it is an interested PCodeOp.
     * @param funcNode the current function node
     * @param pcode the PCodeOp
     * @return true to do abstract interpretation on this PCodeOp
     */
    // TODO: trivial, remove this function in the future
    public boolean isInterestedPCode(FunctionNode funcNode, PcodeOpAST pcode) {
        var intraCtx = intraCtxMap.get(funcNode);
        for (var vn: pcode.getInputs()) {
            if (intraCtx.tracedVarnodes.contains(vn)) {
                return true;
            }
        }
        return false;
    }


    public void updateLoadStoreMap(FunctionNode funcNode, PcodeOp pcodeOp, SymbolExpr symExpr, GeneralType type, boolean isLoad) {
        var intraCtx = intraCtxMap.get(funcNode);
        if (isLoad) {
            var access = new AccessPoint(pcodeOp, symExpr, type);
            intraCtx.allLoads.add(access);
            Logging.debug(String.format("[Load] Found load operation: %s -> %s", symExpr, type));
        } else {
            var access = new AccessPoint(pcodeOp, symExpr, type);
            intraCtx.allStores.add(access);
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
        symbolAliasMap.union(se1, se2);
        Logging.debug(String.format("[Alias] %s -> %s", se1, se2));
    }

    public void updateSymbolAliasMap(SymbolExpr sym1, SymbolExpr sym2) {
        symbolAliasMap.union(sym1, sym2);
        Logging.debug(String.format("[Alias] %s -> %s", sym1, sym2));
    }

    /**
     * Build the complex data type for the HighSymbol based on the load/store maps calculated from intraSolver.
     * All HighSymbol with ComplexType should in the tracedSymbols set.
     * // TODO: 先按照各自的 Symbol 都生成对应的 ComplexType，之后按照 Alias 关系合并，在合并过程中考虑 pCodeOp 的重复带来的影响即可
     */
    public void buildComplexType(FunctionNode funcNode) {
        var intraCtx = intraCtxMap.get(funcNode);

        // Step 1: Create initial ComplexTypes for all involved HighSymbols
        HashSet<HighSymbol> involvedSymbols = new HashSet<>(intraCtx.tracedSymbols);
        Map<HighSymbol, ComplexType> initialComplexTypes = new HashMap<>();
        Consumer<AccessPoint> createComplexType = access -> {
            var highSym = access.symExpr.baseSymbol;
            if (involvedSymbols.contains(highSym)) {
                var complexType = initialComplexTypes.computeIfAbsent(highSym, k -> new ComplexType());
                complexType.addField(access.symExpr.offset, access.type);
            }
        };
        intraCtx.allLoads.forEach(createComplexType);
        intraCtx.allStores.forEach(createComplexType);

        // Step 2: Merge ComplexTypes based on aliasing and distinct PCodeOps
        Map<HighSymbol, ComplexType> mergedComplexTypes = new HashMap<>();
        Map<HighSymbol, Set<AccessPoint>> symbolToAccessPoints = new HashMap<>();
        intraCtx.allLoads.forEach(load -> symbolToAccessPoints.computeIfAbsent(load.symExpr.baseSymbol, k -> new HashSet<>()).add(load));
        intraCtx.allStores.forEach(store -> symbolToAccessPoints.computeIfAbsent(store.symExpr.baseSymbol, k -> new HashSet<>()).add(store));

        for (var component : symbolAliasMap.getComponents().values()) {
            ComplexType mergedType = new ComplexType();
            Set<PcodeOp> usedPcodeOps = new HashSet<>();

            for (SymbolExpr symExpr : component) {
                HighSymbol highSym = symExpr.baseSymbol;
                if (!initialComplexTypes.containsKey(highSym)) continue;
                var accessPoints = symbolToAccessPoints.getOrDefault(highSym, Collections.emptySet());

                for (var ap : accessPoints) {
                    if (!usedPcodeOps.contains(ap.pcodeOp)) {
                        mergedType.addField(ap.symExpr.offset, ap.type);
                        usedPcodeOps.add(ap.pcodeOp);
                    }
                }
            }

            for (SymbolExpr symExpr : component) {
                mergedComplexTypes.put(symExpr.baseSymbol, mergedType);
            }
        }

        // Step 3: Update references to point to the merged ComplexTypes
        symbol2ComplexType.putAll(mergedComplexTypes);
    }


    public boolean isFunctionSolved(FunctionNode funcNode) {
        return intraCtxMap.containsKey(funcNode);
    }


    public void dumpIntraComplexType(FunctionNode funcNode) {
        var intraCtx = intraCtxMap.get(funcNode);
        for (var highSym: intraCtx.tracedSymbols) {
            var complexType = symbol2ComplexType.get(highSym);
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
