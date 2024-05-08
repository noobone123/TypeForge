package blueprint.solver;

import blueprint.base.dataflow.KSet;
import blueprint.base.dataflow.UnionFind;
import blueprint.base.dataflow.type.ComplexType;
import blueprint.base.dataflow.type.GeneralType;
import blueprint.base.node.FunctionNode;
import blueprint.utils.Logging;
import blueprint.base.dataflow.SymbolExpr;

import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
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

        public UnionFind<SymbolExpr> intraAliasMap;

        public IntraContext() {
            this.tracedSymbols = new HashSet<>();
            this.tracedVarnodes = new HashSet<>();
            this.allSymbolExprs = new HashSet<>();
            this.dataFlowFacts = new HashMap<>();
            this.allLoads = new HashSet<>();
            this.allStores = new HashSet<>();
            this.intraAliasMap = new UnionFind<>();
        }
    }

    public HashMap<FunctionNode, IntraContext> intraCtxMap;
    public UnionFind<SymbolExpr> symbolAliasMap;
    public HashMap<HighSymbol, ComplexType> symbol2ComplexType;

    public Context() {
        this.intraCtxMap = new HashMap<>();
        this.symbolAliasMap = new UnionFind<>();
        this.symbol2ComplexType = new HashMap<>();
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
            Logging.debug("[Interested] Add traced varnode: " + vn);
        }
    }


    /**
     * Add DataFlowFact to the current context.
     * @param funcNode the current function node
     * @param vn the varnode which holds the dataflow fact
     * @param highSym the base HighSymbol of the dataflow fact
     * @param offset the offset of the SymbolExpr
     */
    public void addDataFlowFact(FunctionNode funcNode, Varnode vn, HighSymbol highSym, long offset) {
        var intraCtx = intraCtxMap.get(funcNode);
        if (intraCtx == null) {
            Logging.error("Failed to get intraContext for " + funcNode.value.getName());
            return;
        }
        var symbolExpr = new SymbolExpr(highSym, offset);
        var curDataFlowFact = intraCtx.dataFlowFacts.computeIfAbsent(vn, k -> new KSet<>(intraCtx.dataFlowFactKSize));

        if (curDataFlowFact.add(symbolExpr)) {
            Logging.debug("[DataFlow] " + vn + " -> " + curDataFlowFact);
        }
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
                addDataFlowFact(funcNode, vn, symbol, 0);
            }
        }
    }

    /**
     * If current PCodeOp's input varnode in tracedVarnodes, then it is an interested PCodeOp.
     * @param funcNode the current function node
     * @param pcode the PCodeOp
     * @return true to do abstract interpretation on this PCodeOp
     */
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


    public void updateIntraSymbolAliasMap(FunctionNode funcNode, HighSymbol sym1, long off1, HighSymbol sym2, long off2) {
        var symbolAliasMap = intraCtxMap.get(funcNode).intraAliasMap;
        var se1 = new SymbolExpr(sym1, off1);
        var se2 = new SymbolExpr(sym2, off2);
        symbolAliasMap.union(se1, se2);
        Logging.debug(String.format("[Alias] %s -> %s", se1, se2));
    }

    /**
     * Build the complex data type for the HighSymbol based on the load/store maps calculated from intraSolver.
     * All HighSymbol with ComplexType should in the tracedSymbols set.
     */
    public void buildComplexType(FunctionNode funcNode) {
        var intraCtx = intraCtxMap.get(funcNode);
        intraCtx.allLoads.forEach(load -> {
            var pcodeOp = load.pcodeOp;
            var symExpr = load.symExpr;
            var type = load.type;
            var highSym = symExpr.baseSymbol;
            var offset = symExpr.offset;

            if (intraCtx.tracedSymbols.contains(highSym)) {
                var complexType = symbol2ComplexType.computeIfAbsent(highSym, k -> new ComplexType());
                complexType.addField(offset, type);
            }
        });

        intraCtx.allStores.forEach(store -> {
            var pcodeOp = store.pcodeOp;
            var symExpr = store.symExpr;
            var type = store.type;
            var highSym = symExpr.baseSymbol;
            var offset = symExpr.offset;

            if (intraCtx.tracedSymbols.contains(highSym)) {
                var complexType = symbol2ComplexType.computeIfAbsent(highSym, k -> new ComplexType());
                complexType.addField(offset, type);
            }
        });
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
